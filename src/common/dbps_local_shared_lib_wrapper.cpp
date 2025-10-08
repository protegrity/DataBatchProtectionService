#include <iostream>
#include "dbpa_local.h"
#include "dbpa_interface.h"

using dbps::external::DataBatchProtectionAgentInterface;

// Export function for creating new instances of DBPALocal from shared library
extern "C" {
    DataBatchProtectionAgentInterface* create_new_instance() {
        return new dbps::external::LocalDataBatchProtectionAgent();
    }
} // extern "C"

