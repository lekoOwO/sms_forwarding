#pragma once

constexpr bool idf_push_ca_extensions_valid(bool basic_constraints_ca,
                                             bool key_usage_present,
                                             bool key_cert_sign)
{
    return basic_constraints_ca && (!key_usage_present || key_cert_sign);
}
