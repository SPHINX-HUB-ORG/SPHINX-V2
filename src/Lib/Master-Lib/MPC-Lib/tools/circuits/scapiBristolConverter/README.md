SCAPI - BRISTOL Converter
-------------------------

This tool converts a circuit in SCAPI format to a circuit in Bristol foramt and vice versa.

#Usage


In order to convert a circuit first compile the code using the make command.

##Scapi to Bristol

Convert a circuit from SCAPI format to Bristol format is done using the following command:

    ./scapiBristolConverter scapi_to_bristol <scapi_circuit_path> <bristol_circuit_name> <is_multiplarty>
    

* scapi_circuit_path : name of scapi's circuit that should be converted
* bristol_circuit_name : name of bristol's circuit that should be created
* is_multiplarty : a boolean indicates wheather the scapi circuit is in the multi-party or the two party format. 
(Detailed explanation about the formats can be found at libscapi/tools/circuits/README.md)

for example:

    ./scapiBristolConverter scapi_to_bristol scapi_add.txt bristol_add.txt false
    
This will convert a scapi's circuit named scapi_add.txt, which is not in multiparty format 
into a bristol circuit named bristol_add.txt.

## Bristol to Scapi

Convert a circuit from Bristol format to SCAPI format is done using the following command:

    ./scapiBristolConverter bristol_to_scapi <bristol_circuit_name> <scapi_circuit_path> <parties_number> <is_multiplarty>
    

* bristol_circuit_name : name of bristol's circuit that should be converted
* scapi_circuit_path : name of scapi's circuit that should be created
* parties_number : number of parties that participates in the circuit evaluation.
* is_multiplarty : a boolean indicates wheather the scapi circuit shaould be in the multi-party or the two party format. 
(Detailed explanation about the formats can be found at libscapi/tools/circuits/README.md)

for example:

     ./scapiBristolConverter bristol_to_scapi bristol_add.txt scapi_add.txt 2 true
     
This will convert a bristol's circuit named bristol_add.txt, which has two parties into a scapi's circuit in multiparty format named scapi_add.txt.