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

from lib import *

M_STRING_TO_R_STRING = {
    "MBEDTLS_SSL_HELLO_REQUEST": "ID_ST_BEFORE",
    "MBEDTLS_SSL_CLIENT_HELLO": "ID_ST_SR_CLNT_HELLO",
    "MBEDTLS_SSL_SERVER_HELLO": "ID_ST_SW_SRVR_HELLO_ED",
    "MBEDTLS_SSL_ENCRYPTED_EXTENSIONS": "ID_ST_SW_ENCRYPTED_EXTENSIONS_ED",
    "MBEDTLS_SSL_CERTIFICATE_REQUEST": "ID_ST_SW_CERT_REQ_ED",
    "MBEDTLS_SSL_SERVER_CERTIFICATE": "ID_ST_SW_CERT_ED",
    "MBEDTLS_SSL_CERTIFICATE_VERIFY": "ID_ST_SW_CERT_VRFY_ED",
    "MBEDTLS_SSL_SERVER_FINISHED": "ID_ST_SW_FINISHED_ED",
    "MBEDTLS_SSL_CLIENT_CERTIFICATE": "ID_ST_SR_CERT",
    "MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY": "ID_ST_SR_CERT_VRFY",
    "MBEDTLS_SSL_CLIENT_FINISHED": "ID_ST_SR_FINISHED",
    "MBEDTLS_SSL_END_OF_EARLY_DATA": "ID_ST_SR_END_OF_EARLY_DATA",
    "MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET": "ID_ST_SW_SESSION_TICKET_ED",
    "MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET_FLUSH": "ID_ST_SW_SESSION_TICKET_ED",
    "MBEDTLS_SSL_HANDSHAKE_WRAPUP": "ID_ST_SR_FINISHED",
    # "MBEDTLS_SSL_HANDSHAKE_WRAPUP": 55,
    "MBEDTLS_SSL_SERVER_CCS_AFTER_HELLO_RETRY_REQUEST": "ID_ST_SW_CHANGE_ED",
    "MBEDTLS_SSL_SERVER_CCS_AFTER_SERVER_HELLO": "ID_ST_SW_CHANGE_ED",
    "MBEDTLS_SSL_HELLO_RETRY_REQUEST": 56,
    "MBEDTLS_SSL_HANDSHAKE_OVER": "ID_ST_OK",
    "MBEDTLS_EMPTY" : "ID_EMPTY"
}

M_PRIME_NEED_CONVERT = {
    "MBEDTLS_SSL_SERVER_HELLO",
    "MBEDTLS_SSL_ENCRYPTED_EXTENSIONS",
    "MBEDTLS_SSL_CERTIFICATE_REQUEST",
    "MBEDTLS_SSL_SERVER_CERTIFICATE",
    "MBEDTLS_SSL_CERTIFICATE_VERIFY",
    "MBEDTLS_SSL_SERVER_FINISHED",
    "MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET",
    "MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET_FLUSH"
}

SEQ_LENGTH = 40

def load_data_from_file(log_name, key1, key2):
    data = {key1 : [], key2 : []}
    lines = load_file(log_name)
    index = 0
    ids = []
    while lines[index].find(key1) == -1: # Find the first keyword on the line
        index += 1
    while index < len(lines):
        line1 = lines[index]
        line2 = lines[index + 1]
        line3 = lines[index + 2]
        line4 = lines[index + 3]
        key = key1 if line1.find(key1) != -1 else key2
        # line1 = line1[line1.find(key) : line1.find('=')]
        if line1.find(key1) != -1:
            ids.append(load_id_from_string(line1))
        line2 = line2[line2.rfind('[') + 1 : len(line2) - 1]
        line4 = line4[ : line4.find(']')]
        datastream = line2 + line3 + line4
        data[key].append(load_data_from_string(datastream))
        index += 4
    return data, ids

def convert(datalist):
    array_converted = []
    for data in datalist:
        array = []
        for num in data:
            m_state_string = M_STATE_INT_TO_STRING[num]
            r_state_string = M_STRING_TO_R_STRING[m_state_string]
            r_state_int = r_state_string if isinstance(r_state_string, int) else R_STATE_STRING_TO_INT[r_state_string]
            if m_state_string in M_PRIME_NEED_CONVERT:
                array.append(r_state_int - 1)
            if m_state_string in M_PRIME_CHANGE_ED:
                array.append(33) # ID_ST_SW_CHANGE
            array.append(r_state_int)
        array = array[ : SEQ_LENGTH]
        array_converted.append(array)
    return array_converted

# No 2, 3, 5, 6 in mbed (earlydata related)
def remove_23_56(datalist):
    for data in datalist:
        i = 1
        while i < len(data):
            if data[i] == 3 and data[i-1] == 2:
                data.pop(i-1)
                data.pop(i-1)
                i -= 1
            elif data[i] == 6 and data[i-1] == 5:
                data.pop(i-1)
                data.pop(i-1)
                i -= 1
            # elif data[i] == 28:
            #     data.pop(i)
            else:
                i += 1
        while len(data) < SEQ_LENGTH:
            data.append(53)

# Delete 5(req) when s_cert_request(x!3) is 0
def remove19_5_3(datalist, ids):
    for i in range(len(datalist)):
        data = datalist[i]
        index = ids[i]
        if (index >> 3) & 1== 0:
            i = 2
            while i < len(data):
                if data[i] == 3 and data[i-1] == 5 and data[i-2] == 19:
                    data.pop(i-1)
                else:
                    i += 1

# There will be multiple ccs in the mbed, delete the later ccs
def remove_2nd_ccs(datalist):
    for data in datalist:
        i = 0
        flag = 0
        while i < len(data):
            if data[i] >= 22 and data[i] <= 26:
                if flag > 0:
                    data.pop(i)
                flag += 1
            i += 1
        while len(data) < SEQ_LENGTH:
            data.append(53)

# Delete 48-51 in (x!1/\x!3) because serverfinished->cert in RFC requires ~x!1, but not in mbed.
# So the (x!1/\x!3) condition, mbed will go to cert first, and RFC finishes directly
def remove49_50(datalist, ids):
    for i in range(len(datalist)):
        data = datalist[i]
        index = ids[i]
        begin_pos = -1
        end_pos = -1
        if (index >> 1) & 1 and (index >> 3) & 1:
            i = 2
            while i < len(data):
                if data[i] == 51:
                    end_pos = i
                if data[i] == 48:
                    begin_pos = i
                i += 1
            if end_pos > begin_pos > -1:
                for j in range(end_pos - begin_pos -1):
                    data.pop(begin_pos+1)
            while len(data) < SEQ_LENGTH:
                data.append(53)

# 55 (hrr) for 29, 30 (serverhello)
def remove_56(datalist):
    for data in datalist:
        i = 1
        while i < len(data):
            if data[i] == 56:
                data.insert(i,29)
                data[i+1] = 30
                data.pop()
            else:
                i += 1
        while len(data) < SEQ_LENGTH:
            data.append(53)

# Two 51s are encountered, one is deleted, and MBEDTLS_SSL_HANDSHAKE_WRAPUP and MBEDTLS_SSL_CLIENT_FINISHED have the same meaning
def remove_51(datalist):
    for data in datalist:
        i = 1
        while i < len(data):
            if data[i] == 51 and data[i-1] == 51:
                data.pop(i)
            else:
                i += 1
        while len(data) < SEQ_LENGTH:
            data.append(53)

# Delete redundant 45, 46
def remove_45_46(datalist):
    for data in datalist:
        flag = -1
        i = 1
        while i < len(data):
            if data[i] == 46 and data[i-1] == 45:
                flag += 1
                if flag > 0:
                    data.pop(i)
                    data.pop(i - 1)
                    i -= 1
                else:
                    i += 1
            else:
                i += 1
        while len(data) < SEQ_LENGTH:
            data.append(53)


if __name__ == '__main__':
    filename = "../log/server_cmp2"
    data, ids = load_data_from_file(filename + "_init.log", "mbedstatem", "RFCstatem")
    mbedstatem = data["mbedstatem"]
    RFCstatem = data["RFCstatem"]
    # save_to_file11(filename + "_test2.log", RFCstatem, ids)
    remove19_5_3(mbedstatem, ids)
    remove_2nd_ccs(mbedstatem)

    #converted mbed
    seq = convert(mbedstatem)
    # save_to_file11(filename + "_test3.log", seq, ids)
    remove_51(seq)
    remove49_50(seq, ids)
    remove_56(seq)
    remove_23_56(RFCstatem)
    remove_45_46(RFCstatem)
    # save_to_file(filename + "_post2.log", seq, RFCstatem, ids)
    cmp(seq, RFCstatem, ids)