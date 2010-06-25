#ifndef __RTYPES_H__
#define __RTYPES_H__

#include "rtypebase.h"

// Prototype all the rr parser functions here.
rr_data_parser A_1;
rr_data_parser unknown_rtype;

// Add them to the list of data parsers here.
rr_parser_container * rr_parsers[] = {{1, A_1},{}

// This is for handling rr's with errors or an unhandled rtype.
rr_parser_container default_rr_parser = {0, unknown_rtype};

#endif
