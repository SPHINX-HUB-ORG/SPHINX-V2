SCAPI - NEC Converter
-------------------------

This tool converts a circuit in SCAPI format to a circuit in NEC foramt.
Notice that the scapi circuit should be in the multiparty format only. 
This tool does not support convertion from scapi circuit in the two-party format.
(Detailed explanation about the formats can be found at libscapi/tools/circuits/README.md)

#Usage


In order to convert a circuit first compile the code using the make command.

Convert a circuit from SCAPI format to NEC format is done using the following command:

    ./scapiBristolConverter scapi_to_nec <scapi_circuit_path> <nec_circuit_name>
    

* scapi_circuit_path : name of scapi's circuit that should be converted. 
* nec_circuit_name : name of nec's circuit that should be created

for example:

    ./scapiNecConverter scapi_to_nec scapi_add.txt nec_add.txt

    
This will convert a scapi's circuit named scapi_add.txt into a nec circuit named nec_add.txt.
