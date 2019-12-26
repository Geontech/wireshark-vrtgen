import inspect
import os

import jinja2
import yaml

from vrtgen.types import basic
from vrtgen.types import enums
from vrtgen.types import cif0
from vrtgen.types import cif1
from vrtgen.types import struct

JINJA_OPTIONS = {
    'line_statement_prefix': '//%',
    'block_start_string':    '/*%',
    'block_end_string':      '%*/',
    'comment_start_string':  '/*#',
    'comment_end_string':    '#*/'
}

def is_enum(obj):
    # Ignore anything that isn't a BinaryEnum class
    if not inspect.isclass(obj) or not issubclass(obj, enums.BinaryEnum):
        return False
    # Only return concrete enums (i.e., those that have values defined) to
    # filter out abstract base classes (just BinaryEnum at present)
    return bool(obj.__members__)

def split_capitals(name):
    start = 0
    in_word = True
    for index, char in enumerate(name[1:], 1):
        if char.isupper():
            if not in_word:
                yield name[start:index].lower()
                start = index
                in_word = True
        else:
            in_word = False
    yield name[start:].lower()

def c_name(name):
    return '_'.join(split_capitals(name))

def ws_type(dtype):
    if issubclass(dtype, basic.FixedPointType):
        if dtype.bits > 32:
            return 'FT_DOUBLE'
        return 'FT_FLOAT'
    if issubclass(dtype, (basic.IntegerType, basic.NonZeroSize)):
        if dtype.signed:
            sign = ''
        else:
            sign = 'U'
        # Round up to next multiple of 8
        bits = ((dtype.bits + 7) // 8) * 8
        return 'FT_{}INT{}'.format(sign, bits)
    if issubclass(dtype, basic.BooleanType):
        return 'FT_BOOLEAN'
    if issubclass(dtype, enums.BinaryEnum):
        return 'FT_INT32'
    return 'FT_NONE'

def ws_base(dtype):
    if dtype in (basic.Identifier16, basic.Identifier32, basic.StreamIdentifier):
        return 'BASE_HEX'
    if issubclass(dtype, (basic.IntegerType, basic.NonZeroSize)):
        return 'BASE_DEC'
    if issubclass(dtype, enums.BinaryEnum):
        return 'BASE_DEC'
    return 'BASE_NONE'

TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), 'templates')

class CIFModule:
    def __init__(self, name):
        self.name = name
        self.fields = []
        self.trees = []
        self.enables = []
        self.dissectors = []

    def process_enable(self, enable):
        hf_name = 'hf_{}_enables_{}'.format(self.name, enable.attr)
        abbrev = enable.attr + '_en'
        self._add_ws_field(hf_name, enable, abbrev=abbrev, ftype='FT_BOOLEAN', base='BASE_NONE')

        offset = 31 - enable.offset
        self.enables.append({
            'name': enable.name,
            'attr': enable.attr,
            'var': hf_name,
            'offset': offset,
        })

    def _add_ws_field(self, var, field, abbrev=None, ftype=None, base=None):
        if abbrev is None:
            abbrev = '{}.{}'.format(self.name, field.attr)
        if ftype is None:
            ftype = ws_type(field.type)
        if base is None:
            base = ws_base(field.type)
        if issubclass(field.type, enums.BinaryEnum):
            vals = 'VALS({})'.format(c_name(field.type.__name__) + '_str')
        else:
            vals = 'NULL'
        self.fields.append({
            'var': var,
            'name': field.name,
            'abbrev': abbrev,
            'type': ftype,
            'base': base,
            'vals': vals,
            'flags': 0,
        })

    def process_field(self, field):
        # Skip unimplemented fields and enables
        if field.type is None or field.type.bits == 1:
            return

        hf_name = 'hf_{}_{}'.format(self.name, field.attr)
        self._add_ws_field(hf_name, field)

        dissector = self._create_dissector(hf_name, field)
        self.dissectors.append(dissector)

    def _create_dissector(self, var, field):
        dissector = {
            'var': var,
            'name': field.name,
            'attr': field.attr,
            'size': field.type.bits // 8,
        }
        if field.type.bits % 8:
            dissector['packed'] = True
            dissector['bits'] = field.type.bits
        if issubclass(field.type, struct.Struct):
            tree_var = 'ett_{}_{}'.format(self.name, field.attr)
            self.trees.append(tree_var)
            dissector['tree'] = tree_var
            dissector['fields'] = self.process_struct(var, field)
            dissector['struct'] = True
        elif issubclass(field.type, basic.FixedPointType):
            dissector['fixed'] = True
            dissector['bits'] = field.type.bits
            dissector['radix'] = field.type.radix
        return dissector

    def process_struct(self, name, field):
        dissectors = []
        for subfield in field.type.get_fields():
            abbrev = '{}.{}'.format(field.attr, subfield.attr)
            hf_name = '{}_{}'.format(name, subfield.attr)
            self._add_ws_field(hf_name, subfield, abbrev=abbrev)
            dissector = self._create_dissector(hf_name, subfield)
            offset = subfield.word * 32 + (31-subfield.offset)
            dissector['bitoffset'] = offset
            dissector['offset'] = offset // 8
            dissectors.append(dissector)
            offset += field.bits / 8

        return dissectors

class PluginGenerator:
    def __init__(self):
        self.loader = jinja2.FileSystemLoader(TEMPLATE_PATH)
        self.env = jinja2.Environment(loader=self.loader, **JINJA_OPTIONS)
        with open('strings.yml', 'r') as fp:
            self.strings = yaml.safe_load(fp)

    def generate_enums(self, filename):
        template = self.env.get_template('enums.h')
        enum_types = [self.format_enum(en) for _, en in inspect.getmembers(enums, is_enum)]

        with open(filename, 'w') as fp:
            fp.write(template.render({'enums': enum_types}))

    def format_enum_value(self, enum, enum_name, fmt, value):
        section = self.strings['enums'].get(enum.__name__, {})
        text = section.get(value.name, None)
        if not text:
            text = section.get('default', value.name).format(value=value.value, name=value.name)
        return {
            'label': '{}_{}'.format(enum_name.upper(), value.name),
            'value': fmt.format(value.value),
            'string': text,
        }

    def format_enum(self, enum):
        name = c_name(enum.__name__)
        # Create a format string that returns a hex constant
        digits = int((enum.bits + 3) / 4)
        format_string = '0x{{:0{}x}}'.format(digits)
        return {
            'name': name,
            'type': name + '_e',
            'strings': name + '_str',
            'values': [self.format_enum_value(enum, name, format_string, v) for v in enum],
        }

    def generate_cif(self, name, cif, cif_fields):
        template = self.env.get_template('cif.h')
        filename = '{}.h'.format(name)
        fields = []

        module = CIFModule(name)
        for enable in cif_fields.Enables.get_fields():
            module.process_enable(enable)

        for field in cif_fields.get_fields():
            module.process_field(field)

        with open(filename, 'w') as fp:
            fp.write(template.render(package='v49d2', cif=module))

    def generate(self):
        self.generate_enums('enums.h')
        self.generate_cif('cif0', cif0, cif0.CIF0)
        self.generate_cif('cif1', cif1, cif1.CIF1)

if __name__ == '__main__':
    generator = PluginGenerator()
    generator.generate()
