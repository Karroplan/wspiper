#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "../wsp_settings.h"

int init_test_settings(void) {
    return 0;
}

int clean_test_settings(void) {
    return 0;
}

void test_parsestr(void) {

    connect_endpoints* ce1 = NULL;
    char* test_str1 = "[eth0]ws://example.com:8080/path";

    CU_ASSERT(parse_str_to_addrs(test_str1, &ce1) == 0);
    CU_ASSERT_STRING_EQUAL(ce1->bind_interface, "eth0");

}

int main() {

   CU_pSuite pSuite = NULL;

   /* initialize the CUnit test registry */
   if (CUE_SUCCESS != CU_initialize_registry())
      return CU_get_error();

   /* add a suite to the registry */
   pSuite = CU_add_suite("Settings", init_test_settings, clean_test_settings);
   if (NULL == pSuite) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   /* add the tests to the suite */
   /* NOTE - ORDER IS IMPORTANT - MUST TEST fread() AFTER fprintf() */
   if (
        (NULL == CU_add_test(pSuite, "test of parsestr()", test_parsestr))
    )
   {
      CU_cleanup_registry();
      return CU_get_error();
   }

   /* Run all tests using the CUnit Basic interface */
   CU_basic_set_mode(CU_BRM_VERBOSE);
   CU_basic_run_tests();
   CU_cleanup_registry();
   return CU_get_error();

    return 0;
}