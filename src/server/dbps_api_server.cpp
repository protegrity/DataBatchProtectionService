#include <crow/app.h>

int main() {
    crow::SimpleApp app;

    CROW_ROUTE(app, "/healthz")([] {
        return "OK";
    });

    CROW_ROUTE(app, "/statusz")([]{
        crow::json::wvalue response;
        response["status"] = "chill";
        response["system_settings"] = "set to thrill!";
        return response;
    });

    // Encryption endpoint - POST /encrypt
    CROW_ROUTE(app, "/encrypt").methods("POST"_method)([](const crow::request& req) {
        crow::json::wvalue response;

        // Build data_batch_encrypted structure
        crow::json::wvalue data_batch_encrypted;
        data_batch_encrypted["value_format"]["compression"] = "ZSTD";
        data_batch_encrypted["value"] = "RW5jcnlwdGVkQmFzZTY0QmxvYg==";
        response["data_batch_encrypted"] = std::move(data_batch_encrypted);

        // Build access structure
        crow::json::wvalue access;
        access["user_id"] = "user123";
        access["role"] = "EmailReader";
        access["access_control"] = "granted";
        response["access"] = std::move(access);

        // Build debug structure
        crow::json::wvalue debug;
        debug["reference_id"] = "550e8400-e29b-41d4-a716-446655440000";
        response["debug"] = std::move(debug);

        return response;
    });

    // Decryption endpoint - POST /decrypt
    CROW_ROUTE(app, "/decrypt").methods("POST"_method)([](const crow::request& req) {
        crow::json::wvalue response;

        // Build data_batch structure
        crow::json::wvalue data_batch;
        data_batch["datatype"] = "BYTE_ARRAY";
        data_batch["value_format"]["compression"] = "UNCOMPRESSED";
        data_batch["value_format"]["format"] = "raw-c-data";
        data_batch["value_format"]["encoding"] = "base64";
        data_batch["value"] = "dXNlcjFAZXhhbXBsZS5jb20KdXNlcjJAZXhhbXBsZS5jb20K";
        response["data_batch"] = std::move(data_batch);

        // Build access structure
        crow::json::wvalue access;
        access["user_id"] = "user123";
        access["role"] = "EmailReader";
        access["access_control"] = "granted";
        response["access"] = std::move(access);

        // Build debug structure
        crow::json::wvalue debug;
        debug["pretty_printed_value"] = "user1@example.com\nuser2@example.com";
        debug["reference_id"] = "de305d54-75b4-431b-adb2-eb6b9e546014";
        response["debug"] = std::move(debug);

        return response;
    });

    app.port(18080).multithreaded().run();
}
