//
// Created by liork on 17/09/17.
//

/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*
* Copyright (c) 2016 LIBSCAPI (http://crypto.biu.ac.il/SCAPI)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
*
* Libscapi uses several open source libraries. Please see these projects for any further licensing issues.
* For more information , See https://github.com/cryptobiu/libscapi/blob/master/LICENSE.MD
*
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*
*/



#ifndef LIBSCAPI_MEASURE_HPP
#define LIBSCAPI_MEASURE_HPP

#include <string>
#include <chrono>
#include <fstream>
#include <iostream>
#include <exception>
#include <memory>
#include <unistd.h>
#include <stdio.h>
#include <tuple>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <iomanip>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include "ConfigFile.hpp"
#include "json.hpp"

class Protocol;

using namespace std;
using namespace std::chrono;
using json = nlohmann::json;

class Measurement {
public:
    Measurement(Protocol &protocol);
    Measurement(Protocol &protocol, vector<string> &names);
    Measurement(const string &protocolName, int internalIterationsNumber, int partyId, int partiesNumber);
    Measurement(const string & protocolName, int internalIterationsNumber, int partyId, int partiesNumber,
                vector<string> & names);
    void addTaskNames(vector<string> & names);
    ~Measurement();
    void startSubTask(const string &taskName, int currentIterationNum);
    void endSubTask(const string &taskName, int currentIterationNum);
    void writeData(const string &key, const string &value);
    void analyzeComm(const json & j, const string &fileName);


private:
    string getcwdStr() {
        char buff[255];//automatically cleaned when it exits scope
        return string(getcwd(buff,255));
    }

    void init(Protocol &protocol);
    void init(const vector <string> &names);
    void setTaskNames(const vector<string> & names);
    void init(const string &protocolName, int internalIterationsNumber, int partyId, int partiesNumber);
    int getTaskIdx(const string &name); // return the index of given task name

    void analyze(); // create JSON file with cpu times
    void analyzeMemory();
    void createJsonFile(const json &j, const string &fileName);

    vector<vector<double>> *m_cpuStartTimes;
    vector<vector<double>> *m_cpuEndTimes;
    vector<vector<double>> *m_memoryUsage;
    vector<string> m_names;
    vector<pair<string, string>> m_arguments;
    map<string, string> m_auxiliaryData;

    string m_protocolName;
    int m_partyId = 0;
    int m_numOfParties;
    int m_numberOfIterations;
};


#endif //LIBSCAPI_MEASURE_HPP
