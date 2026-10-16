// Imports a function nobody provides, to exercise unresolved-symbol handling.
void missing_fn(void);
int calls_missing(void) { missing_fn(); return 0; }
int does_not_call_missing(void) { return 5; }
