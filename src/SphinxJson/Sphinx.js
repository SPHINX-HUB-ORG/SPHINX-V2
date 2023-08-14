// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.

// Include library
const jsonrpc = require('.jsonrpcpp/include/jsonrpcpp.hpp');
const SPHINXContractInterface = require('../Consensus/interface.hpp');

class Sphinx {
    constructor(serverEndpoint, options = {}) {
        this.serverEndpoint = serverEndpoint;
        this.options = options;
        this.contractInterface = new SPHINXContractInterface(serverEndpoint, options);
        this.client = new jsonrpc.Client();
    }

    async sendRequest(method, params) {
        try {
            const result = await this.client.call(this.serverEndpoint, method, params);
            return result;
        } catch (error) {
            throw new Error(`Request error: ${error.message}`);
        }
    }

    // Example method using sendRequest
    async exampleMethod() {
        return this.sendRequest('exampleMethod', []);
    }

    // Call an RPC method
    async callRpcMethod(method, params) {
        return this.sendRequest(method, params);
    }

    // Estimate gas for a transaction
    async estimateGas(txData) {
        return this.callRpcMethod('estimateGas', [txData]);
    }

    // Encode a contract call
    async encodeContractCall(methodName, args) {
        // Implement contract call encoding logic
      
        const abi = await getContractAbi(contractAddress);
        const methodAbi = abi.find((abiItem) => abiItem.name === methodName);
      
        if (!methodAbi) {
            throw new Error(`Method ${methodName} not found in contract ABI`);
        }
      
        const encodedCall = abiCoder.encodeFunction(methodAbi, args);
      
        return encodedCall;
    }
      
    // Decode an event log
    async decodeEventLog(eventAbi, logData) {
        // Implement event log decoding
      
        const event = abiCoder.decodeLog(eventAbi, logData);
      
        return event;
    }
      
    // Subscribe to an event
    subscribeToEvent(contractAddress, eventName, callback) {
        // Implement event subscription logic here
        // You might need to use a library to manage event subscriptions
      
        const eventSubscription = new EventSubscription(contractAddress, eventName, callback);
      
        eventSubscription.start();
      
        return eventSubscription;
    }      

    // Configuration methods...

    // Set gas price
    setGasPrice(gasPrice) {
        this.options.gasPrice = gasPrice;
    }

    // Set default sender
    setDefaultSender(sender) {
        this.options.defaultSender = sender;
    }

    // Set network ID
    setNetworkId(networkId) {
        this.options.networkId = networkId;
    }
    
    // Set API key
    setApiKey(apiKey) {
        this.options.apiKey = apiKey;
    }

    // Other configuration options...

    // Caching methods
    // Initialize cache
    initializeCache() {
        this.cache = {};
    }

    // Get cached value
    getCached(key) {
        return this.cache[key];
    }

    // Set cached value
    setCached(key, value) {
        this.cache[key] = value;
    }

    // Clear cached value
    clearCached(key) {
        delete this.cache[key];
    }

    // Interact with the smart contract interface
    async interactWithSmartContractInterface(contractAddress, methodName, args) {
        return this.contractInterface.callContractMethod(contractAddress, methodName, args);
    }
}

module.exports = Sphinx;