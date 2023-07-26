import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Random;


/**
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy) 
 *
 */
public class GenerateArithmeticCircuitForDepthAndGates {
	
	static int numOfGates;
	static int numOfMultGates;
	static int depth;
	static int numOfParties;
	static int numberOfAllPartiesInputs;
	static boolean outputOne;
	

	static int layerSize;
	
	static int numberOfOutputWires;
	
	static int numOfWires;
	
	static int wireIndex;
	static String fileName;
	static BufferedWriter outBuffer;
	
	static Random rn = new Random();
	
	
	
	/**
	 * The main function that creates the circuit. It actually almost runs the creation twice. Once in order to gather data that should be written
	 * in the header of the file, and the other time to actually write to the circuit file.
	 * 
	 */
	public static void main(String[] args) throws IOException {
		
		
		numOfGates = Integer.parseInt(args[0]);
		numOfMultGates = Integer.parseInt(args[1]);
		
		depth = Integer.parseInt(args[2]);
		numOfParties = Integer.parseInt(args[3]);
		int numOfPartyWires = Integer.parseInt(args[4]);
		int numOfOutputWires = Integer.parseInt(args[5]);
		
		outputOne = Boolean.parseBoolean(args[6]);
		numberOfAllPartiesInputs = numOfPartyWires*numOfParties;
		
		layerSize = numOfGates/depth+1;

		
		numberOfOutputWires = Math.min(layerSize, numOfOutputWires);
		
		numOfWires = numOfGates + numberOfAllPartiesInputs;
		
		wireIndex = numberOfAllPartiesInputs;
		
		
		
		
		//get the file name of the original 2 party circuit
		if(outputOne)
			fileName = "" + numOfGates + "G_" + numOfMultGates + "MG_" + numOfPartyWires+ "In_"+ numberOfOutputWires + "Out_" + depth + "D_" + "OutputOne" +  numOfParties + "P.txt";
		else
			fileName = "" + numOfGates + "G_" + numOfMultGates + "MG_" + numOfPartyWires+ "-I_"+ numberOfOutputWires + "-O_" + depth + "D_" + "OutputAll" +  numOfParties + "P.txt";
		
		
		createCircuit(fileName);
	}
	
	

	public static void createCircuit(String fileName) throws IOException {
		//the first index of the newly created wire is the ondex after the input wires of the two parties
		//create the real file of the circuit
		FileWriter fstream = new FileWriter(fileName);
		outBuffer = new BufferedWriter(fstream);
		
		
		//write the header of the circtuit file, that is, the number of gates, wires and inputs to party one and two.
		writeHeadderOfCircuitFile();
		
		generateFirstLayer();
		
		generateLastLayers();
		
		//close the buffer
		outBuffer.close();
	}


	/**
	 * This function is responsible for writing the header of the file which includes data such, number of gates, wires for each party and  output wires.
	 * @throws IOException
	 */
	private static void writeHeadderOfCircuitFile()
			throws IOException {
		//the header of the file. 
		
		
		//write the #Gates #parties #wires
		outBuffer.write("" + numOfGates +  "\n");
		outBuffer.write( numOfParties +  "\n");
		
		outBuffer.write("\n" );
		//write the input wires of each  party
		
		
		for(int i=0; i<numOfParties; i++){
		
			outBuffer.write("" + (i+1)  + " " + numberOfAllPartiesInputs/numOfParties + "\n");
			for(int j=0; j<numberOfAllPartiesInputs/numOfParties; j++){
				outBuffer.write("" + ((numberOfAllPartiesInputs/numOfParties)*i +  j) +  "\n");
			}
			outBuffer.write("\n");
		}
		
		
		
		
		if(outputOne){
		//write the outputs
		outBuffer.write("1 "  + numberOfOutputWires + "\n" );	
		
		//get the output indices
			for(int i = 0; i<numberOfOutputWires ; i++){
				outBuffer.write("" +(numOfWires - numberOfOutputWires + i)   + "\n" );
			}
			
			outBuffer.write("\n");
			
			for(int i=1; i<numOfParties;i++){
				outBuffer.write((i+1) + " 0"  + "\n\n" );
			}
		}
		else{
			for(int i = 0; i<numOfParties ; i++){
				outBuffer.write("" + (i + 1) +" "  + numberOfOutputWires + "\n" );	
				for(int j = 0; j<numberOfOutputWires ; j++){
					outBuffer.write("" +(numOfWires - numberOfOutputWires + j)   + "\n" );
				}
			}
		}
		
		
		
		outBuffer.write("\n");
	}

	
	
	public static void generateFirstLayer() throws IOException{

		//calc the number of times we choose each wire
		int timesToChoose = (int) Math.ceil((double)(layerSize) / (double)numberOfAllPartiesInputs);
		int iterateToNum;
		
		
		if(timesToChoose==1){
			iterateToNum = layerSize;
		}
		else
			iterateToNum = numberOfAllPartiesInputs;
		
		int numOfMult = numOfMultGates/depth;
		int indexOfMults = 0;
		
		

		for(int i = 0; i<iterateToNum;i++){
			for(int j = 0; j<timesToChoose ; j++){
				
				if(indexOfMults<numOfMult){
					outBuffer.write("2 1 " + i + " " + getRand(i, numberOfAllPartiesInputs - 1) + " " + wireIndex + " 2" + "\n");
					indexOfMults++;
				}
				else{
					outBuffer.write("2 1 " + i + " " + getRand(i, numberOfAllPartiesInputs - 1) + " " + wireIndex + " 1" + "\n");
				}
				
				wireIndex++;
				
				
			}
			
			if(wireIndex == numberOfAllPartiesInputs + layerSize)
				break;
				
			
		}

	}
	
	public static void generateLastLayers() throws IOException{

		//calc the number of layers we need to generate 
		
		int lastIndexOfLayer, firstIndexOfLayer;
		
		int numOfMult = numOfMultGates/depth;
		int indexOfMults = 0;
		
		
		for(int i = 0; i<depth-1;i++){
			lastIndexOfLayer = wireIndex;
			firstIndexOfLayer = wireIndex - layerSize;
			
			indexOfMults = 0;
			for(int j = 0; j<layerSize ; j++){
				if(indexOfMults<numOfMult){
					outBuffer.write("2 1 " + (firstIndexOfLayer + j) + " " + (firstIndexOfLayer + j) /*getRand(firstIndexOfLayer + j, lastIndexOfLayer - 1)*/ + " " + wireIndex + " 2" + "\n");
					indexOfMults++;
				}
				else{
					outBuffer.write("2 1 " + (firstIndexOfLayer + j) + " " + getRand(firstIndexOfLayer + j, lastIndexOfLayer - 1) + " " + wireIndex + " 1" + "\n");
				}
				wireIndex++;
				
		
				if(wireIndex==numOfWires)//no need to generate anymore gates.
					return;
			}
			
		}
		
		
	}
	
	
	public static int getRand(int notToChoose, int max){
		
		int rand = notToChoose;
		
		while(rand==notToChoose)
			rand = Math.abs(rn.nextInt() % max);

		return rand;
		
	}
	
}
