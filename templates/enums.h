#ifndef ENUMS_H
#define ENUMS_H
/*% for enum in enums %*/
typedef enum {
/*%-    for value in enum['values'] %*/
    {{value.label}} = {{value.value}},
/*%-    endfor %*/
} {{enum.type}};

const value_string {{enum.strings}}[] = {
/*%-    for value in enum['values'] %*/
    { {{value.label}}, "{{value.string}}" },
/*%-    endfor %*/
    { 0, NULL }
};
/*% endfor %*/
#endif /* ENUMS_H */
