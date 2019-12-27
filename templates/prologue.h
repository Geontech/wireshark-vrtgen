#ifndef PROLOGUE_H
#define PROLOGUE_H

/*% include "dissector.h" %*/

/*% for struct in module.structs %*/
typedef struct {
/*%-    for field in struct.fields %*/
    {{field.type}} {{field.attr}};
/*%-    endfor %*/
} {{struct.name}}_t;
/*% endfor %*/

#endif
