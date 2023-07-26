//
// Created by moriya on 24/09/17.
//
#include <../../include/cryptoInfra/Protocol.hpp>

string CmdParser::getKey(const string & parameter)
{
    if (parameter[0] == '-')
        return parameter.substr(1);
    else
        return parameter;
}


string CmdParser::getValueByKey(vector<pair<string, string>> arguments, string key)
{
    int size = arguments.size();
    for (int i = 0; i < size; ++i)
    {
        pair<string, string> p = arguments[i];
        if (p.first == key)
            return p.second;
    }
    return "NotFound";
}

vector<pair<string, string>> CmdParser::parseArguments(string protocolName, int argc, char* argv[])
{

    //Put the protocol name in the vector pairs
    vector<pair<string, string>> arguments;
    arguments.push_back(make_pair("protocolName", protocolName));

    //Put all other parameters in the map
    for(int i=1; i<argc; i+=2)
    {
        string key(getKey(string(argv[i])));
        string value(getKey(string(argv[i+ 1])));
        pair <string, string> p = make_pair(key, value);
        arguments.emplace_back(p);

        cout<<"key = "<< key <<" value = "<< value <<endl;
    }

    return arguments;
}

Protocol::Protocol(string protocolName, int argc, char* argv[])
{
    arguments = parser.parseArguments(protocolName, argc, argv);
}

vector<pair<string, string>> Protocol::getArguments()
{
    return arguments;
}

CmdParser Protocol::getParser()
{
    return parser;
}

MPCProtocol::MPCProtocol(string protocolName, int argc, char* argv[], bool initComm):
             Protocol (protocolName, argc, argv){

    vector<string> subTaskNames{"Offline", "Online"};
    timer = new Measurement(*this, subTaskNames);

    auto partiesNumber = this->getParser().getValueByKey(arguments, "partiesNumber");

    if (partiesNumber == "NotFound")
        numParties = 2;
    else
    {
        try
        {
            numParties = stoi(this->getParser().getValueByKey(arguments, "partiesNumber"));
        }
        catch (const invalid_argument& ia)
        {
            cout << "Invalid value for partiesNumber: " << ia.what() << endl;
        }

    }
    cout<<"number of parties = "<<numParties<<endl;

    try
    {
        partyID = stoi(this->getParser().getValueByKey(arguments, "partyID"));
        if(partyID >= numParties)
            exit(-1);
    }
    catch (const invalid_argument& ia)
    {
        cout << "Invalid value for party ID: " << ia.what() << endl;
    }
    cout << "ID = " << partyID << endl;

    auto partiesFile = this->getParser().getValueByKey(arguments, "partiesFile");
    cout<<"partiesFile = "<<partiesFile<<endl;

    auto internalIterationsNumber = this->getParser().getValueByKey(arguments, "internalIterationsNumber");
    if (internalIterationsNumber == "NotFound")
        times = 1;
    else
    {
        try
        {
            times = stoi(internalIterationsNumber);
        }
        catch (const invalid_argument& ia)
        {
            cout << "Invalid value for internalIterationsNumber: " << ia.what() << endl;
        }
    }


    if (initComm)
        parties = comm.setCommunication(partyID, numParties, partiesFile);
    auto isNumThreads = this->getParser().getValueByKey(arguments, "numThreads");
    if(isNumThreads == "NotFound")
        numThreads = 1;
    else
    {
        try
        {
            numThreads = stoi(this->getParser().getValueByKey(arguments, "numThreads"));
        }
        catch (const invalid_argument& ia)
        {
            cout << "Invalid value for numThreads: " << ia.what() << endl;
        }

    }

    //Calculates the number of threads.
    if (numParties <= numThreads){
        this->numThreads = numParties;
        numPartiesForEachThread = 1;
    } else
        numPartiesForEachThread = (numParties + numThreads - 1)/ numThreads;
}


MPCProtocol::~MPCProtocol()
{
    json party = json::array();
    for (int idx = 0; idx < parties.size(); idx++) {
        if(partyID == idx) continue;

        json commData = json::object();
        commData["partyId"] = idx;
        commData["bytesSent"] = parties[idx].get()->bytesOut;
        commData["bytesReceived"] = parties[idx].get()->bytesIn;
        party.insert(party.end(), commData);
    }
    string fileName = "party" + to_string(partyID) + "CommData.json";
    timer->analyzeComm(party, fileName);

    if(timer != nullptr)
        delete timer;
}

void MPCProtocol::initTimes(){
    byte tmpBytes[20];
    byte allBytes[20*numParties];
    roundFunctionSameMsg(tmpBytes, allBytes, 20);

}

void MPCProtocol::run(){

    for (currentIteration = 0; currentIteration<times; currentIteration++){
        initTimes();
        timer->startSubTask("Offline", currentIteration);
        runOffline();
        timer->endSubTask("Offline", currentIteration);

        timer->startSubTask("Online", currentIteration);
        runOnline();
        timer->endSubTask("Online", currentIteration);

    }


}

void MPCProtocol::roundFunctionSameMsg(byte* sendData, byte* receiveData, size_t msgSize){
    vector<thread> threads(numThreads);
    //Split the work to threads. Each thread gets some parties to work on.
    for (int t=0; t<numThreads; t++) {
        if ((t + 1) * numPartiesForEachThread <= parties.size()) {
            threads[t] = thread(&MPCProtocol::exchangeDataSameInput, this, sendData, receiveData,
                    t * numPartiesForEachThread, (t + 1) * numPartiesForEachThread, msgSize);
        } else {
            threads[t] = thread(&MPCProtocol::exchangeDataSameInput, this, sendData, receiveData,
                    t * numPartiesForEachThread, numParties, msgSize);
        }
    }
    for (int t=0; t<numThreads; t++){
        threads[t].join();
    }
}


void MPCProtocol::roundFunctionDiffMsg(byte* sendData, byte* receiveData, int msgSize){
    vector<thread> threads(numThreads);
    //Split the work to threads. Each thread gets some parties to work on.
    for (int t=0; t<numThreads; t++) {
        if ((t + 1) * numPartiesForEachThread <= parties.size()) {
            threads[t] = thread(&MPCProtocol::exchangeDataDiffInput, this, sendData, receiveData,
                    t * numPartiesForEachThread, (t + 1) * numPartiesForEachThread, msgSize);
        } else {
            threads[t] = thread(&MPCProtocol::exchangeDataDiffInput, this, sendData, receiveData,
                    t * numPartiesForEachThread, numParties, msgSize);
        }
    }
    for (int t=0; t<numThreads; t++){
        threads[t].join();
    }
}

void MPCProtocol::exchangeDataSameInput(byte* sendData, byte* receiveData, int first, int last, int msgSize){
    for (int j=first; j<last; j++){
        if (partyID < j) {
            //send myData to the other party
            parties[j]->write(sendData, msgSize);
            //receive the other data from the other party
            parties[j]->read(receiveData + j*msgSize, msgSize);

        } else if (partyID > j){
            //receive the other data from the other party
            parties[j]->read(receiveData + j*msgSize, msgSize);
            //send myData to the other party
            parties[j]->write(sendData, msgSize);
        } else {
            memcpy(receiveData + j*msgSize, sendData, msgSize);
        }
    }
}

void MPCProtocol::exchangeDataDiffInput(byte* sendData, byte* receiveData, int first, int last, int msgSize){
    for (int j=first; j<last; j++){
        if (partyID < j) {
            //send myData to the other party
            parties[j]->write(sendData + j*msgSize, msgSize);
            //receive the other data from the other party
            parties[j]->read(receiveData + j*msgSize, msgSize);

        } else if (partyID > j){
            //receive the other data from the other party
            parties[j]->read(receiveData + j*msgSize, msgSize);
            //send myData to the other party
            parties[j]->write(sendData + j*msgSize, msgSize);
        } else {
            memcpy(receiveData + j*msgSize, sendData + j*msgSize, msgSize);
        }
    }
}

