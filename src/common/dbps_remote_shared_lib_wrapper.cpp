#include <iostream>
#include "dbpa_remote.h"
#include "dbpa_interface.h"

using dbps::external::DataBatchProtectionAgentInterface;

// Export function for creating new instances of DBPARemotefrom shared library
extern "C" {
    DataBatchProtectionAgentInterface* create_new_instance() {
        return new dbps::external::RemoteDataBatchProtectionAgent();
    }
} // extern "C"
