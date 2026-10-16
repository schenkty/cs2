#include <stdlib.h>
#include <math.h>
int game_tick(void);
int game_spawn(void);
int main(int argc, char **argv) { (void)argv; game_spawn(); return game_tick() + (int)sqrt((double)argc) + (getenv("X") != NULL); }
