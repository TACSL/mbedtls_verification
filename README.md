# Formal Verification of TLS 1.3 Handshake State Machine in MbedTLS

This is the source code repo for our project, which conducts the equvalence verfication of TLS 1.3 state machine：

1) described in the standard (RFC 8446), and
2) implemented in the Mbed-TLS (v3.6.1).

This instruction describes the organization of the source code and how to use it.

## Software Requirements

- To run the RFC and Mbed-TLS Cryptol formal model of TLS 1.3 state machine, you need [cryptol 3.1.0+](https://cryptol.net/).
- To generate state transition sequences of RFC and Mbed-TLS Cryptol formal model, you need [SAW](https://saw.galois.com/).
- To verify equivalence between the Mbed-TLS formal model and the C code implementations, you need [SAW](https://saw.galois.com/).

## File Organization

**Source code files:**

- Mbed-TLS Fromal Model, in the directory ``cry/``
  - ``Def.cry`` : definition of Mbed-TLS handshake state identifiers, structures, and other configurations
  - ``client_statem.cry`` : the formal model of Mbed-TLS client TLS 1.3 handshake state machine
  - ``server_statem.cry`` : the formal model of Mbed-TLS server TLS 1.3 handshake state machine
  - ``statem.cry`` : the Cryptol model of the Mbed-TLS state controller, which calls the client and server state machines above, and outputs the state transition sequence
- Verification between Mbed-TLS and C,  in the directory ``c_and_cry/``
  - ``statemDef.saw`` : the script for the common import files and structures needed to run SAW
  - ``client_statem.saw`` : the script for verifying the equvalence between OpenSSL formal models and C code implementations of the client TLS 1.3 handshake state machine
  - ``server_statem.saw`` : the script for verifying the equvalence between OpenSSL formal models and C code implementations of the server TLS 1.3 handshake state machine
  - ``client_statem.bc`` : the bitcode file containing all functions of the client TLS 1.3 handshake state machine
  - `` server_statem.bc`` : the bitcode file containing all functions of the server TLS 1.3 handshake state machine
  - ``log/`` : the results of equivalence verification
- Verification between Mbed-TLS and RFC, in the directory ``rfc_and_cry/``
  - `` RFC_Model/`` : RFC Fromal Model, which was transplanted from *Formal Verification of TLS 1.3 Handshake State Machine in OpenSSL*.
    - ``definition.cry`` : definition of RFC handshake message and state identifiers
    - ``state_machine.cry``  : the state construction and state search function required for the execution of state machine
    -  ``client_state_machine.cry`` : the formal model of client TLS 1.3 handshake state machine
    -  ``server_state_machine.cry`` : the formal model of server TLS 1.3 handshake state machine
  - *Cryptol model source code*
    - ``cry_source/`` : the same files in directory ``cry/``, except that the configuration items are written into the structure, and only consider the legitimate cases of state transitions
  - *Tools for generating state transition sequences*
    - ``conf.cry`` : generate RFC Cryptol models and Mbed-TLS Cryptol models instantiated with all negotiation parameter combinations
    - ``client_run.saw`` : generate the client TLS 1.3 handshake state transition sequences for RFC Cryptol models and Mbed-TLS Cryptol models, with 32 each
    - ``server_run.saw`` : generate the server TLS 1.3 handshake state transition sequences for RFC Cryptol models and Mbed-TLS Cryptol models, with 128 each
  - ``post_process/`` : the scripts for processing and comparing state transition sequences
    - ``lib.py`` :  the list of corresponding states in Mbed-TLS Cryptol model and RFC Cryptol  model
    - ``client_process.py`` : processing and comparing client state transition sequences
    - ``server_process.py`` : processing and comparing server state transition sequences
  - ``log/`` : the results of generating the state transition sequence

## The Execution of Mbed-TLS Model Alone

You can use the following commands to run the OpenSSL Cryptol model once in the console for revision and testing.

```
PROJECTROOTDIR> cd cry
PROJECTROOTDIR/cry> Cryptol
Cryptol> :l [filename].cry
Cryptol> mbedtls_ssl_tls13_handshake_client_step S 0 0  /  mbedtls_ssl_tls13_handshake_server_step S 0 0 0
```

## The Execution of SAW

You can use the following commands to run the SAWScript to verify the equvalence between Mbed-TLS formal models and C code implementations, and output the results to the file.

```
PROJECTROOTDIR> cd c_and_cry
PROJECTROOTDIR/c_and_cry> saw [filename].saw > [filename].log
```

Please move the files in `` PROJECTROOTDIR/rfc_and_cry/cry_source`` to ``PROJECTROOTDIR/rfc_and_cry``. Then, you can use the following commands to run the SAWScript to generate the state trasnsion sequences of RFC and Mbed-TLS Cryptol formal model, and output the results to the file. 

```
PROJECTROOTDIR> cd rfc_and_cry
PROJECTROOTDIR/rfc_and_cry> saw [filename].saw > [filename].log
```

