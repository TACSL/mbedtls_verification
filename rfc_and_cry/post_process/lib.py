#    Copyright 2026 wxl904@bupt.edu.cn

#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at

#        http://www.apache.org/licenses/LICENSE-2.0

#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

M_STATE_STRING_TO_INT = {
    "MBEDTLS_SSL_HELLO_REQUEST": 0,
    "MBEDTLS_SSL_CLIENT_HELLO": 1,
    "MBEDTLS_SSL_SERVER_HELLO": 2,
    "MBEDTLS_SSL_SERVER_CERTIFICATE": 3,
    "MBEDTLS_SSL_SERVER_KEY_EXCHANGE": 4,
    "MBEDTLS_SSL_CERTIFICATE_REQUEST": 5,
    "MBEDTLS_SSL_SERVER_HELLO_DONE": 6,
    "MBEDTLS_SSL_CLIENT_CERTIFICATE": 7,
    "MBEDTLS_SSL_CLIENT_KEY_EXCHANGE": 8,
    "MBEDTLS_SSL_CERTIFICATE_VERIFY": 9,
    "MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC": 10,
    "MBEDTLS_SSL_CLIENT_FINISHED": 11,
    "MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC": 12,
    "MBEDTLS_SSL_SERVER_FINISHED": 13,
    "MBEDTLS_SSL_FLUSH_BUFFERS": 14,
    "MBEDTLS_SSL_HANDSHAKE_WRAPUP": 15,
    "MBEDTLS_SSL_NEW_SESSION_TICKET": 16,
    "MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT": 17,
    "MBEDTLS_SSL_HELLO_RETRY_REQUEST": 18,
    "MBEDTLS_SSL_ENCRYPTED_EXTENSIONS": 19,
    "MBEDTLS_SSL_END_OF_EARLY_DATA": 20,
    "MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY": 21,
    "MBEDTLS_SSL_CLIENT_CCS_AFTER_SERVER_FINISHED": 22,
    "MBEDTLS_SSL_CLIENT_CCS_BEFORE_2ND_CLIENT_HELLO": 23,
    "MBEDTLS_SSL_SERVER_CCS_AFTER_SERVER_HELLO": 24,
    "MBEDTLS_SSL_CLIENT_CCS_AFTER_CLIENT_HELLO": 25,
    "MBEDTLS_SSL_SERVER_CCS_AFTER_HELLO_RETRY_REQUEST": 26,
    "MBEDTLS_SSL_HANDSHAKE_OVER": 27,
    "MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET": 28,
    "MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET_FLUSH": 29,
    "MBEDTLS_EMPTY": 53
}

M_STATE_INT_TO_STRING = {v : k for k, v in M_STATE_STRING_TO_INT.items()}

R_STATE_STRING_TO_INT = {
    "ID_ST_ERROR": 0,
    "ID_ST_BEFORE": 1,
    "ID_ST_EARLY_DATA": 2,
    "ID_ST_EARLY_DATA_ED": 3,
    "ID_ST_OK": 4,
    "ID_ST_PENDING_EARLY_DATA_END": 5,
    "ID_ST_PENDING_EARLY_DATA_END_ED": 6,
    "ID_ST_CW_CLNT_HELLO": 7,
    "ID_ST_CW_CLNT_HELLO_ED": 8,
    "ID_ST_CW_CHANGE": 9,
    "ID_ST_CW_CHANGE_ED": 10,
    "ID_ST_CW_END_OF_EARLY_DATA": 11,
    "ID_ST_CW_END_OF_EARLY_DATA_ED": 12,
    "ID_ST_CW_CERT": 13,
    "ID_ST_CW_CERT_ED": 14,
    "ID_ST_CW_CERT_VRFY": 15,
    "ID_ST_CW_CERT_VRFY_ED": 16,
    "ID_ST_CW_FINISHED": 17,
    "ID_ST_CW_FINISHED_ED": 18,
    "ID_ST_CW_KEY_UPDATE": 19,
    "ID_ST_CW_KEY_UPDATE_ED": 20,
    "ID_ST_CR_SRVR_HELLO": 21,
    "ID_ST_CR_ENCRYPTED_EXTENSIONS": 22,
    "ID_ST_CR_CERT_REQ": 23,
    "ID_ST_CR_CERT": 24,
    "ID_ST_CR_CERT_VRFY": 25,
    "ID_ST_CR_FINISHED": 26,
    "ID_ST_CR_KEY_UPDATE": 27,
    "ID_ST_CR_SESSION_TICKET": 28,
    "ID_ST_SW_SRVR_HELLO": 29,
    "ID_ST_SW_SRVR_HELLO_ED": 30,
    "ID_ST_SW_ENCRYPTED_EXTENSIONS": 31,
    "ID_ST_SW_ENCRYPTED_EXTENSIONS_ED": 32,
    "ID_ST_SW_CHANGE": 33,
    "ID_ST_SW_CHANGE_ED": 34,
    "ID_ST_SW_CERT_REQ": 35,
    "ID_ST_SW_CERT_REQ_ED": 36,
    "ID_ST_SW_CERT": 37,
    "ID_ST_SW_CERT_ED": 38,
    "ID_ST_SW_CERT_VRFY": 39,
    "ID_ST_SW_CERT_VRFY_ED": 40,
    "ID_ST_SW_FINISHED": 41,
    "ID_ST_SW_FINISHED_ED": 42,
    "ID_ST_SW_KEY_UPDATE": 43,
    "ID_ST_SW_KEY_UPDATE_ED": 44,
    "ID_ST_SW_SESSION_TICKET": 45,
    "ID_ST_SW_SESSION_TICKET_ED": 46,
    "ID_ST_SR_CLNT_HELLO": 47,
    "ID_ST_SR_END_OF_EARLY_DATA": 48,
    "ID_ST_SR_CERT": 49,
    "ID_ST_SR_CERT_VRFY": 50,
    "ID_ST_SR_FINISHED": 51,
    "ID_ST_SR_KEY_UPDATE": 52,
    "ID_EMPTY": 53
}

M_PRIME_CHANGE_ED = {
    "MBEDTLS_SSL_CLIENT_CCS_AFTER_SERVER_FINISHED",
    "MBEDTLS_SSL_CLIENT_CCS_BEFORE_2ND_CLIENT_HELLO",
    "MBEDTLS_SSL_SERVER_CCS_AFTER_SERVER_HELLO",
    "MBEDTLS_SSL_CLIENT_CCS_AFTER_CLIENT_HELLO",
    "MBEDTLS_SSL_SERVER_CCS_AFTER_HELLO_RETRY_REQUEST"
}

R_STATE_INT_TO_STRING = {v : k for k, v in R_STATE_STRING_TO_INT.items()}

def check_charset(file_path):
    import chardet
    with open(file_path, "rb") as f:
        data = f.read(4)
        charset = chardet.detect(data)['encoding']
    return charset

def load_file(file_name):
    encoding_charset = check_charset(file_name)
    try:
        with open(file_name, 'r', encoding=encoding_charset) as f:
            lines = f.readlines()
            return lines
    except FileNotFoundError:
        print(f"No such file :\n{file_name}")
        exit()

def load_data_from_string(st):
    st += ','
    array = [int(st[ : st.find(',')])]
    while st.find(' ') != -1:
        st = st[st.find(' ') + 1 : ]
        num = int(st[ : st.find(',')])
        array.append(num)
    return array

def load_id_from_string(st):
    begin = st.rfind('[')
    end = st.rfind(']')
    id_str = st[begin+1:end]
    id = int(id_str)
    return id


def save_to_file(file_name, mbed, rfc, ids):
    with open(file_name, 'w', encoding='utf-8') as f:
        for i in range(len(mbed)):
            f.write(f"mbedstatem{ids[i]} = " + str(mbed[i]) + "\n")
            f.write(f"RFCstatem{ids[i]} = " + str(rfc[i]) + "\n")
            f.flush()

def save_to_file11(file_name, mbed, ids):
    with open(file_name, 'w', encoding='utf-8') as f:
        for i in range(len(mbed)):
            f.write(f"mbedstatem{ids[i]} = " + str(mbed[i]) + "\n")
            f.flush()

def cmp(mbed, rfc, ids):
    num_equal_count = 0
    num_count = 0
    seq_equal_count = 0
    for i in range(len(mbed)):
        count = 0
        for j in range(len(mbed[i])):
            if mbed[i][j] == rfc[i][j]:
                count += 1
                num_equal_count += 1
            num_count += 1
        if count == len(mbed[i]):
            seq_equal_count += 1
        else:
            print(f"{ids[i]}:{bin(ids[i])}")
            # print(mbed[i])
            # print(rfc[i])
    print(seq_equal_count)
    print(num_equal_count)
    print(num_count)