import inspect
import os

import jinja2
import yaml

from vrtgen.types import enums
from vrtgen.types import cif0
from vrtgen.types import cif1

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

TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), 'templates')

class PluginGenerator:
    def __init__(self):
        self.loader = jinja2.FileSystemLoader(TEMPLATE_PATH)
        self.env = jinja2.Environment(loader=self.loader, **JINJA_OPTIONS)
        #self.strings = RawConfigParser()
        #self.strings.optionxform = str
        #self.strings.read('strings.cfg')
        with open('strings.yml', 'r') as fp:
            self.strings = yaml.safe_load(fp)

    # def get_string(self, *path, fallback=None):
    #     section = self.strings
    #     value = fallback
    #     for name in path:
    #         child = section.get(name, None)
    #         if not child:
    #             return fallback

    def generate_enums(self, filename):
        template = self.env.get_template('enums.h')
        enum_types = [self.format_enum(en) for _, en in inspect.getmembers(enums, is_enum)]

        with open(filename, 'w') as fp:
            fp.write(template.render({'enums': enum_types}))

    def format_enum_value(self, enum, enum_name, fmt, value):
        section = self.strings['enums'].get(enum.__name__, {})
        return {
            'label': '{}_{}'.format(enum_name.upper(), value.name),
            'value': fmt.format(value.value),
            'string': section.get(value.name, value.name)
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

    def generate_cif(self, cif, enables):
        template = self.env.get_template('cif.h')
        filename = '{}.h'.format(cif)
        with open(filename, 'w') as fp:
            fp.write(template.render({
                'name': cif,
                'fields': enables.get_fields()
            }))

    def generate(self):
        self.generate_enums('enums.h')
        self.generate_cif('cif0', cif0.CIF0.Enables)
        self.generate_cif('cif1', cif1.CIF1.Enables)

if __name__ == '__main__':
    generator = PluginGenerator()
    generator.generate()
