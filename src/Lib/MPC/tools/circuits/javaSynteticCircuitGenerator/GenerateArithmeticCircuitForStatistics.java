import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

/**
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy) 
 *
 */
public class GenerateArithmeticCircuitForStatistics {
	
	static int numOfParties;
	static int numOfSamples;
	static int numberOfTypes;
	static int numOfInputs;
	
	static int numberOfOutputWires; 
	
	static int numOfWires;
	
	static int wireIndex;
	static String fileName;
	static BufferedWriter outBuffer;
	
	static int[] arrayInd;
	
	static int multCounter = 0;
	
	
	
	/**
	 * The main function that creates the circuit. It actually almost runs the creation twice. Once in order to gather data that should be written
	 * in the header of the file, and the other time to actually write to the circuit file.
	 * 
	 */
	public static void main(String[] args) throws IOException{
		
		
		
		numOfParties = Integer.parseInt(args[0]);
		numberOfTypes = Integer.parseInt(args[1]);
		numOfSamples= Integer.parseInt(args[2]);
		
		numOfInputs = wireIndex = numOfParties*numOfSamples*numberOfTypes*2;//numberOfPartyInputWires;
		
		//get the file name of the original 2 party circuit
		fileName = "ArithmeticStatistics" +numberOfTypes +"Pairs"+ "And" + numOfSamples+"SamplesFor" + numOfParties + "Parties.txt";
		
		numberOfOutputWires = numberOfTypes*5;
		
		
		createCircuit(fileName);
		
		System.out.println("the num of mults is: " + multCounter);
	}
	
	

	public static void createCircuit(String fileName) throws IOException {
		//the first index of the newly created wire is the ondex after the input wires of the two parties
		//create the real file of the circuit
		FileWriter fstream = new FileWriter(fileName);
		outBuffer = new BufferedWriter(fstream);
		
		
		//write the header of the circtuit file, that is, the number of gates, wires and inputs to party one and two.
		writeHeadderOfCircuitFile();
		
		initPrameters();
		
		
		//create a xi^2 for all items
		firstLayerOfMults(arrayInd);
		
		int sumofX = 0;
		int sumofY = 0;
		
		
		for(int i=0; i<numberOfTypes; i++){
			
			for(int a=0; a<2; a++){
				for(int j=0; j<numOfParties*numOfSamples; j++){
					arrayInd[j] = 2* j + i*numOfSamples*numOfParties*2 +a ;
				}
				
				wireIndex = generateSum(arrayInd,wireIndex);
				
				int sum = wireIndex -1;
				
				if(a%2==0){
					sumofX = sum;
				}
				else{
					sumofY = sum;
				}
				
				
				
				for(int j=0; j<numOfParties*numOfSamples; j++){
					arrayInd[j] =numOfInputs + 2* j + i*numOfSamples*numOfParties*2 +a;
				}
				
				//create the sum of the squares we have created in the begining
				wireIndex = generateSum(arrayInd,wireIndex); 
				
				int sumOfSquares = wireIndex -1;
				
				
				
				
				//square the resulting wire
				outBuffer.write("2 1 " + sum+ " " + sum + " " + wireIndex + " 2" + "\n");
				
				multCounter++;
				int sumToThePowerOf2 = wireIndex; 
				wireIndex++;
				
				//smult
				outBuffer.write("2 1 " + sumOfSquares+ " " + numOfParties*numOfSamples + " " + wireIndex + " 5" + "\n");
				wireIndex++;
				
				//last gate that subtracts the two parts sum(xi^2) - N(sum(xi))^2
				outBuffer.write("2 1 " + (wireIndex - 1)+ " " + sumToThePowerOf2+ " " + wireIndex + " 6" + "\n");
				wireIndex++;
			}
			
			
			//calc sum(xy)
				

			for(int j=0; j<numOfParties*numOfSamples; j++){
				arrayInd[j] = numOfInputs*2  + numOfParties*numOfSamples*i + j ;
			}
			
			//create the sum of the squares we have created in the begining
			wireIndex = generateSum(arrayInd,wireIndex);
			int sumOfXY = wireIndex-1;
			
			
			outBuffer.write("2 1 " + sumofX+ " " + sumofY + " " + wireIndex + " 2" + "\n");
			multCounter++;
			int productOfSumXandY = wireIndex;
			wireIndex++;
			 
			
			
			//smult
			outBuffer.write("2 1 " + sumOfXY+ " " + numOfParties*numOfSamples + " " + wireIndex + " 5" + "\n");
			wireIndex++;
			
			//last gate that subtracts the two parts sum(xi^2) - N(sum(xi))^2
			outBuffer.write("2 1 " + (wireIndex - 1)+ " " + productOfSumXandY+ " " + wireIndex + " 6" + "\n");
			wireIndex++;
				
				
			
				
			
			//
		}
		
		


		//close the buffer
		outBuffer.close();
	}
	
	
	private static void firstLayerOfMults(int[] input) throws IOException{
		
		
		for(int i=0; i<numOfInputs; i++){
			
			outBuffer.write("2 1 " + i + " " + i + " " + wireIndex + " 2" + "\n");
			multCounter++;
			wireIndex++;
		}
		
		
		for(int i=0; i<numOfInputs/2; i++){
			
			outBuffer.write("2 1 " + (2*i) + " " + (2*i +1) + " " + wireIndex + " 2" + "\n");
			multCounter++;
			wireIndex++;
		}
		
		
	}


	/**
	 * This function is responsible for writing the header of the file which includes data such, number of gates, wires for each party and  output wires.
	 * @throws IOException
	 */
	private static void writeHeadderOfCircuitFile()
			throws IOException {
		//the header of the file. 
		
		
		//write the #Gates #parties #wires
		
		int numOfGates = numOfInputs*3/2 + //number of mult gates
				(numOfParties*numOfSamples-1)*2*numberOfTypes +
				(numOfParties*numOfSamples+2)*3*numberOfTypes;
				
				
				
		outBuffer.write("" + numOfGates +  "\n");
		outBuffer.write( numOfParties +  "\n");
		
		outBuffer.write("\n" );
		//write the input wires of each  party
		
		
		for(int i=0; i<numOfParties; i++){
		
			outBuffer.write("" + (i+1)  + " " + numberOfTypes*numOfSamples*2 + "\n");
			for(int k=0; k<numberOfTypes; k++){
				for(int j=0; j<numOfSamples*2; j++){
				
					outBuffer.write("" + (i*numOfSamples*2 + k*numOfSamples*numOfParties*2 + j) +  "\n");
				}
			}
			outBuffer.write("\n");
		}
		
		
		int offset = numOfInputs*5/2 -1;
		//write the outputs
		outBuffer.write("1 "  + numberOfOutputWires + "\n" );
		
		//get the output indices
		for(int i = 0; i<numberOfOutputWires ; i++){
			
			if(i%5==0 || i%5==2){
				
				offset +=numOfParties*numOfSamples-1;
			}
			else if(i%5==1 || i%5==3 ||i%5==4){
				
				offset += numOfParties*numOfSamples+2;
			}
			
			//outBuffer.write("" + (offset-1) + "\n" );
			outBuffer.write("" + offset + "\n" );
		}
		
		outBuffer.write("\n");
		
		for(int i=1; i<numOfParties;i++){
			outBuffer.write((i+1) + " 0"  + "\n\n" );
		}
		
		
		
		outBuffer.write("\n");
	}

	public static void initPrameters(){
		
		arrayInd = new int[numOfParties*numOfSamples];
		
		for(int i=0; i<numOfParties*numOfSamples; i++){
			arrayInd[i] = i;
		}
	}
	
	
	public static int generateSum(int[] input, int index) throws IOException{
		
		
		int indexStart =  index;
		int isRemainder =  input.length % 2;
		int isRemainderFirst = input.length % 2;
		int isRemainderSecond = 0;
		int remainderFirst = -1;
		int remainderSecond = -1;
		
		if(isRemainderFirst==1){
			//last element
			remainderFirst = input[input.length - 1];
		}

		int size = input.length;
		
		while (size!=0){
			
			size= size/2;
			
			
				isRemainder = size %2;
			for(int i=0; i<size; i++){
				
				outBuffer.write("2 1 " + input[2*i] + " " + input[(2*i+1)] + " " + index + " 1" + "\n");
				input[i] = index;
				index++;
			}
			
			if(isRemainder==1){
				if(isRemainderFirst!=1){
					isRemainderFirst = 1;
					remainderFirst = input[size-1];
				}
					
				else{
					isRemainderSecond = 1;
					remainderSecond = input[size-1];
					
					outBuffer.write("2 1 " + remainderFirst + " " + remainderSecond + " " + index + " 1" + "\n");
					
					isRemainderFirst = 1;
					remainderFirst = index;
					
					index++;
					
					isRemainderSecond = -1;
					
					
				}
			
				
			}
			
			
		}
		return index;
	}
	
	

}
