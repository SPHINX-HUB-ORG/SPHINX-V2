#Java synthetic circuit generator

This tool creates a synthetic circuits.

We support two different types of circuits:
* Circuit based on given depth and number of gates
* Statistics Circuit

##Usage

We supply a runnable jar file for each circuit type. 

##Circuit based on given depth and number of gates

Creates a circuit based on a given depth and number of gates. In order to generate the circuit run the command:

    java -jar synteticDepthAndGatesCircuitGenerator.jar <gates_number> <mult_gates_number> <depth> <parties_number> <number_inputsForEachParty> <outputs_number> <is_output_private>
    

* gates_number : number of required gates in the generated circuit
* mult_gates_number : number of required multiply gates in the generated circuit
* depth : requierd depth of the generated circuit
* parties_number : number of parties in the generated circuit
* number_inputsForEachParty : number of required input wires for each party in the generated circuit
* outputs_number: number of required output wires in the generated circuit
* is_output_private : true - in case the output wires belong to the first party only. false - in case the output wires shared among all parties.


for example:

    java -jar synteticDepthAndGatesCircuitGenerator.jar 20 8 4 2 2 1 true
    
This will create a circuit with twenty gates, eight of them are multiply gates, with four levels. There are two parties execute the circuit and each one has two input wires. The circuit has one output wire that belong to party one only.

##Statistics Circuit

Creates a statistics circuit that gets as input pairs (X,Y) and outputs the following values:
1. SUM(Xi)
2. SUM(Xi^2) - N(SUM(Xi))^2 (in order to calculate the variance of X one should divide this by N*(N-1))
3. SUM(Yi)
4. SUM(Yi^2) - N(SUM(Yi))^2 (in order to calculate the variance of Y one should divide this by N*(N-1))
5. SUM(XiYi) - N*SUM(Xi)*SUM(Yi) (in order to calculate the co-variance of XY one should divide this by N*(N-1))
 

In order to generate the circuit run the command:

    java -jar synteticStatisticsCircuitGenerator.jar <parties_number> <types_number(pairs)> <samples_number>
    

* parties_number : number of parties in the generated circuit
* types_number(pairs) : number of kinds of pairs that are sampled
* samples_number: number of pairs that will be given to the circuit

for example:

    java -jar synteticStatisticsCircuitGenerator.jar 10 1 200

    
This will create a circuit with ten participates, one type pair and 200 samples.