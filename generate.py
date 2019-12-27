import inspect
import os

import jinja2
import yaml

from vrtgen.types import basic
from vrtgen.types import enums
from vrtgen.types import cif0
from vrtgen.types import cif1
from vrtgen.types import prologue
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
        return 'FT_UINT32'
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

class DissectorModule:
    def __init__(self, protocol, name):
        self.protocol = protocol
        self.name = name
        self.fields = []
        self.trees = []
        self.dissectors = []

    def _get_abbrev(self, *names):
        return '.'.join((self.protocol, *names))

    def _add_ws_field(self, var, field, abbrev=None, ftype=None, base=None):
        if abbrev is None:
            abbrev = self._get_abbrev(field.attr)
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

    def _add_tree(self, *names):
        tree_var = '_'.join(('ett', self.protocol, *names))
        self.trees.append(tree_var)
        return tree_var

    def _field_name(self, *names):
        return '_'.join(('hf', self.protocol, *names))

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
            tree_var = self._add_tree(field.attr)
            dissector['tree'] = tree_var
            dissector['fields'] = self.process_struct(field.attr, field.type)
            dissector['struct'] = True
        elif issubclass(field.type, basic.FixedPointType):
            dissector['fixed'] = True
            dissector['bits'] = field.type.bits
            dissector['radix'] = field.type.radix
        return dissector

    def process_struct(self, name, structdef):
        dissectors = []
        for subfield in structdef.get_fields():
            abbrev = self._get_abbrev(name, subfield.attr)
            hf_name = self._field_name(name, subfield.attr)
            self._add_ws_field(hf_name, subfield, abbrev=abbrev)
            dissector = self._create_dissector(hf_name, subfield)
            offset = subfield.word * 32 + (31-subfield.offset)
            dissector['bitoffset'] = offset
            dissector['offset'] = offset // 8
            dissectors.append(dissector)
            offset += structdef.bits / 8

        return dissectors

    def process_header(self, name, structdef):
        hf_name = self._field_name(name)
        item_name = 'V49.2 {}'.format(' '.join(split_capitals(structdef.__name__)))
        self.fields.append({
            'var': hf_name,
            'name': item_name,
            'abbrev': self._get_abbrev(name),
            'type': 'FT_UINT32',
            'base': 'BASE_HEX',
            'vals': 'NULL',
            'flags': 0,
        })

        dissector = {
            'var': self._field_name(name),
            'name': name,
            'attr': name,
            'size': structdef.bits // 8,
        }

        tree_var = self._add_tree(name)
        dissector['tree'] = tree_var
        dissector['struct'] = True
        dissector['fields'] = self.process_struct(name, structdef)

        self.dissectors.append(dissector)

    def process_field(self, field):
        hf_name = self._field_name(field.attr)
        self._add_ws_field(hf_name, field)

        dissector = self._create_dissector(hf_name, field)
        self.dissectors.append(dissector)

class CIFModule(DissectorModule):
    def __init__(self, protocol, name, desc):
        super().__init__(protocol, name)
        self.enables = []

        # Create a field and subtree for the CIF enables
        self.enable_index = self._field_name(self.name, 'enables')
        self.fields.append({
            'var': self.enable_index,
            'name': desc,
            'abbrev': self._get_abbrev(self.name),
            'type': 'FT_UINT32',
            'base': 'BASE_HEX',
            'vals': 'NULL',
            'flags': 0,
        })
        self.tree_index = self._add_tree(self.name)

    def process_enable(self, enable):
        hf_name = self._field_name(self.name, 'enables', enable.attr)
        abbrev = self._get_abbrev('enables', enable.attr)
        self._add_ws_field(hf_name, enable, abbrev=abbrev, ftype='FT_BOOLEAN', base='BASE_NONE')

        offset = 31 - enable.offset
        self.enables.append({
            'name': enable.name,
            'attr': enable.attr,
            'var': hf_name,
            'offset': offset,
        })

    def process_field(self, field):
        # Skip unimplemented fields and enables
        if field.type is None or field.type.bits == 1:
            return
        super().process_field(field)

class PluginGenerator:
    def __init__(self, protocol='v49d2'):
        self.loader = jinja2.FileSystemLoader(TEMPLATE_PATH)
        self.env = jinja2.Environment(loader=self.loader, **JINJA_OPTIONS)
        self.protocol = protocol
        basedir = os.path.dirname(__file__)
        strings_file = os.path.join(basedir, 'strings.yml')
        with open(strings_file, 'r') as fp:
            self.strings = yaml.safe_load(fp)

    def generate_enums(self, filename):
        template = self.env.get_template('enums.h')
        enum_types = [self._format_enum(en) for _, en in inspect.getmembers(enums, is_enum)]

        with open(filename, 'w') as fp:
            fp.write(template.render(enums=enum_types))

    def _format_enum_value(self, enum, enum_name, fmt, value):
        section = self.strings['enums'].get(enum.__name__, {})
        text = section.get(value.name, None)
        if not text:
            text = section.get('default', value.name).format(value=value.value, name=value.name)
        return {
            'label': '{}_{}'.format(enum_name.upper(), value.name),
            'value': fmt.format(value.value),
            'string': text,
        }

    def _format_enum(self, enum):
        name = c_name(enum.__name__)
        # Create a format string that returns a hex constant
        digits = int((enum.bits + 3) / 4)
        format_string = '0x{{:0{}x}}'.format(digits)
        return {
            'name': name,
            'type': name + '_e',
            'strings': name + '_str',
            'values': [self._format_enum_value(enum, name, format_string, v) for v in enum],
        }

    def generate_cif(self, name, cif, cif_fields):
        template = self.env.get_template('cif.h')
        filename = '{}.h'.format(name)

        cif_name = '{} {}'.format(name[:3].upper(), name[3:])
        module = CIFModule(self.protocol, name, cif_name)
        for enable in cif_fields.Enables.get_fields():
            module.process_enable(enable)

        for field in cif_fields.get_fields():
            module.process_field(field)

        with open(filename, 'w') as fp:
            fp.write(template.render(module=module, cif=module))

    def generate_header(self):
        template = self.env.get_template('dissector.h')
        filename = 'prologue.h'
        module = DissectorModule(self.protocol, 'prologue')
        module.process_header('header', prologue.Header)
        module.process_header('data_header', prologue.DataHeader)
        module.process_header('context_header', prologue.ContextHeader)
        module.process_header('command_header', prologue.CommandHeader)
        module.process_field(prologue.Prologue.class_id)

        with open(filename, 'w') as fp:
            fp.write('#ifndef PROLOGUE_H\n')
            fp.write('#define PROLOGUE_H\n')
            fp.write(template.render(module=module, cif=module))
            fp.write('\n#endif\n')

    def generate(self):
        self.generate_enums('enums.h')
        self.generate_cif('cif0', cif0, cif0.CIF0)
        self.generate_cif('cif1', cif1, cif1.CIF1)
        self.generate_header()

if __name__ == '__main__':
    generator = PluginGenerator()
    generator.generate()
