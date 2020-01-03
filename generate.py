# Copyright (C) 2019 Geon Technologies, LLC
#
# This file is part of wireshark-vrtgen.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import inspect
import os

import jinja2
import yaml

from vrtgen.types import basic
from vrtgen.types import cif0
from vrtgen.types import cif1
from vrtgen.types import control
from vrtgen.types import enums
from vrtgen.types import prologue
from vrtgen.types import struct
from vrtgen.types import trailer

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

def is_discrete_io(field):
    return field in (cif1.CIF1.discrete_io_32, cif1.CIF1.discrete_io_64)

def ws_type(field):
    if issubclass(field.type, basic.FixedPointType):
        if field.type.bits > 32:
            return 'FT_DOUBLE'
        return 'FT_FLOAT'
    if issubclass(field.type, (basic.IntegerType, basic.NonZeroSize)):
        # Discrete I/O fields are bitfields and should be displayed as hex,
        # which Wireshark insists must be unsigned (the field types should get
        # fixed in a future version of vrtgen)
        if field.type.signed and not is_discrete_io(field):
            sign = ''
        else:
            sign = 'U'
        # Round up to next multiple of 8
        bits = ((field.type.bits + 7) // 8) * 8
        return 'FT_{}INT{}'.format(sign, bits)
    if issubclass(field.type, basic.BooleanType):
        return 'FT_BOOLEAN'
    if issubclass(field.type, enums.BinaryEnum):
        return 'FT_UINT32'
    return 'FT_NONE'

HEX_TYPES = (
    basic.Identifier16,
    basic.Identifier32,
    basic.StreamIdentifier,
    basic.OUI,
    control.MessageIdentifier,
)

DEC_TYPES = (
    basic.IntegerType,
    basic.NonZeroSize,
    enums.BinaryEnum,
)

def ws_base(field):
    if is_discrete_io(field):
        return 'BASE_HEX'
    if issubclass(field.type, HEX_TYPES):
        return 'BASE_HEX'
    if issubclass(field.type, DEC_TYPES):
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
        self.structs = []

    def _get_abbrev(self, *names):
        return '.'.join((self.protocol, *names))

    def _create_ws_field(self, attr, name, ftype, base, parent=None):
        if parent is None:
            var = self._field_name(attr)
            abbrev = self._get_abbrev(attr)
        else:
            var = self._field_name(parent, attr)
            abbrev = self._get_abbrev(parent, attr)
        return {
            'attr': attr,
            'var': var,
            'name': name,
            'abbrev': abbrev,
            'type': ftype,
            'base': base,
            'vals': 'NULL',
            'flags': 0,
        }

    def _add_tree(self, *names):
        tree_var = '_'.join(('ett', self.protocol, *names))
        self.trees.append(tree_var)
        return tree_var

    def _field_name(self, *names):
        return '_'.join(('hf', self.protocol, *names))

    def _process_struct_fields(self, name, structdef):
        fields = []
        for subfield in structdef.get_contents():
            if isinstance(subfield, struct.Reserved):
                continue
            field = self.add_field(subfield, parent=name)
            bit_offset = subfield.word * 32 + (31-subfield.offset)
            field['bitoffset'] = bit_offset
            field['offset'] = bit_offset // 8
            fields.append(field)

        return fields

    def add_field(self, field, parent=None):
        ftype = ws_type(field)
        base = ws_base(field)
        name = field.name
        if isinstance(field, struct.Enable):
            name += ' Enabled'
        ws_field = self._create_ws_field(field.attr, name, ftype, base, parent=parent)
        if issubclass(field.type, enums.BinaryEnum):
            ws_field['vals'] = 'VALS({})'.format(c_name(field.type.__name__) + '_str')
        ws_field['size'] = field.type.bits // 8
        if field.type.bits % 8:
            ws_field['packed'] = True
            ws_field['bits'] = field.type.bits
        elif issubclass(field.type, basic.FixedPointType):
            ws_field['fixed'] = True
            ws_field['bits'] = field.type.bits
            ws_field['radix'] = field.type.radix
        self.fields.append(ws_field)
        return ws_field

    def add_dissector(self, field, show_hex=False):
        return self.add_struct_dissector(field.attr, field.name, field.type, show_hex)

    def add_struct_dissector(self, attr, name, structdef, show_hex=False):
        if show_hex:
            ftype = 'FT_UINT{}'.format(structdef.bits)
            base = 'BASE_HEX'
        else:
            ftype = 'FT_NONE'
            base = 'BASE_NONE'

        ws_field = self._create_ws_field(attr, name, ftype, base)
        ws_field['dissector'] = 'dissect_{}'.format(attr)
        ws_field['size'] = structdef.bits // 8
        self.fields.append(ws_field)

        dissector = {
            'var': ws_field['var'],
            'name': attr,
            'size': structdef.bits // 8,
            'tree': self._add_tree(attr),
            'fields': self._process_struct_fields(attr, structdef),
        }
        self.dissectors.append(dissector)

        return ws_field

    def add_data_struct(self, name, structdef, unpack=True):
        """
        Add a structure type to be unpacked from the Wireshark packet buffer.
        """
        fields = []
        for field in structdef.get_contents():
            offset = 31 - field.offset
            fields.append({
                'type': 'int',
                'attr': field.attr,
                'offset': offset,
                'bits': field.bits,
            })
        self.structs.append({'name':name, 'fields':fields, 'unpack':unpack})

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

    def generate_cif(self, name, cif):
        template = self.env.get_template('cif.h')
        filename = '{}.h'.format(name)

        cif_name = '{} {}'.format(name[:3].upper(), name[3:])
        module = DissectorModule(self.protocol, name)
        enables = '{}_{}'.format(name, 'enables')
        module.add_struct_dissector(enables, cif_name, cif.Enables, show_hex=True)
        module.add_data_struct(enables, cif.Enables)

        cifs = []
        for field in cif.get_fields():
            # Skip unimplemented fields and enables
            if field.type is None or field.type.bits == 1:
                continue

            if issubclass(field.type, struct.Struct):
                ws_field = module.add_dissector(field)
            else:
                ws_field = module.add_field(field)
            cifs.append(ws_field)

        with open(filename, 'w') as fp:
            fp.write(template.render(module=module, cifs=cifs))

    def _process_header(self, module, header, unpack=True):
        name = c_name(header.__name__)
        item_name = 'V49.2 {}'.format(' '.join(split_capitals(header.__name__)))
        module.add_struct_dissector(name, item_name, header, show_hex=True)
        module.add_data_struct(name, header, unpack)

    def generate_header(self):
        template = self.env.get_template('prologue.h')
        filename = 'prologue.h'

        module = DissectorModule(self.protocol, 'prologue')
        self._process_header(module, prologue.Header)
        self._process_header(module, prologue.DataHeader, unpack=False)
        self._process_header(module, prologue.ContextHeader, unpack=False)
        self._process_header(module, prologue.CommandHeader, unpack=False)

        module.add_field(prologue.Prologue.stream_id)
        module.add_dissector(prologue.Prologue.class_id)
        module.add_dissector(control.CommandPrologue.cam, show_hex=True)
        module.add_data_struct('cam', control.ControlAcknowledgeMode)
        module.add_field(control.CommandPrologue.message_id)
        module.add_field(control.CommandPrologue.controllee_id)
        module.add_field(control.CommandPrologue.controller_id)

        with open(filename, 'w') as fp:
            fp.write(template.render(module=module))

    def generate_trailer(self):
        template = self.env.get_template('trailer.h')
        filename = 'trailer.h'

        module = DissectorModule(self.protocol, 'trailer')
        module.add_struct_dissector('trailer', 'Trailer', trailer.Trailer, show_hex=True)

        with open(filename, 'w') as fp:
            fp.write(template.render(module=module))

    def generate(self):
        self.generate_enums('enums.h')
        self.generate_cif('cif0', cif0.CIF0)
        self.generate_cif('cif1', cif1.CIF1)
        self.generate_header()
        self.generate_trailer()

if __name__ == '__main__':
    generator = PluginGenerator()
    generator.generate()
