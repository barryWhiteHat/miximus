#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

char* _sha256Constraints();
char* _sha256Witness();
char* prove(bool path[][256], int address, bool _address_bits[], int tree_depth, int fee, char* pk);
void genKeys(int tree_depth, char* pkOutput, char* vkOuput );

void helloWorld( char* input);



#ifdef __cplusplus
} // extern "C"
#endif
