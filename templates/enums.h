#ifndef ENUMS_H
#define ENUMS_H
/*% for enum in enums %*/
typedef enum {
/*%-    for value in enum['values'] %*/
    {{value.label}} = {{value.value}},
/*%-    endfor %*/
} {{enum.type}};

const gchar* {{enum.strings}}[] = {
/*%-    for value in enum['values'] %*/
    "{{value.string}}", /* {{value.label}} */
/*%-    endfor %*/
};
/*% endfor %*/
#endif /* ENUMS_H */
