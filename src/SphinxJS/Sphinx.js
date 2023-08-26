// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.



// Include necessary libraries
const jsonrpc = require('.jsonrpcpp/include/jsonrpcpp');
const SPHINXContractInterface = require('../Consensus/interface');
const jsonrpc = require('../Json/src/jsonrpccpp/client/connectors');

const EventSubscription = require('./EventSubscription'); // Import the EventSubscription class

const SPHINXFees = require('./fees'); // Import the SPHINXFees namespace from "fees.cpp"

class Sphinx {
    constructor(serverEndpoint, options = {}) {
        this.serverEndpoint = serverEndpoint;
        this.options = {
            gasPrice: 1000000000, // Default gas price in wei
            networkId: 1,         // Default network ID (mainnet)
            spxGasMultiplier: 1,  // Multiplier for SPX-based gas fees
            // ... other default options
            ...options,
        };

        this.contractInterface = new SPHINXContractInterface(serverEndpoint, options);
        this.client = new jsonrpc.Client();
        this.feesNamespace = SPHINXFees; // Store the imported namespace for later use
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

    // Call the exposed JSON-RPC method in asset.cpp
    async transferSPX(assetId, newOwner, payer) {
        const client = new jsonrpc.Client();
        const method = 'transferSPX_JSONRPC'; // Use the JSON-RPC method name exposed in C++
        const params = [assetId, newOwner, payer];

        try {
            const result = await client.call(this.serverEndpoint, method, params);
            return result; // The result returned by the JSON-RPC method on the C++ side
        } catch (error) {
            throw new Error(`Error transferring SPX: ${error.message}`);
        }
    }
      
    // Subscribe to an event
    subscribeToEvent(contractAddress, eventName, callback) {
        // Implement event subscription logic here
        // You might need to use a library to manage event subscriptions
      
        const eventSubscription = new EventSubscription(contractAddress, eventName, callback);
      
        eventSubscription.start();
      
        return eventSubscription;
    }      

    // Validation and Error Handling
    setGasPrice(gasPrice) {
        if (typeof gasPrice !== 'number' || gasPrice <= 0) {
            throw new Error('Gas price must be a positive number');
        }
        this.options.gasPrice = gasPrice;
        return this; // Allow chaining
    }
    
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

    /* Set Timeout */
    setTimeout(timeout) {
        this.options.timeout = timeout;
    }

    /* Enable/Disable Debugging */
    setRetryOptions(retryOptions) {
        this.options.retryOptions = retryOptions;
    }

    /* Set Retry Mechanism */
    setDebugMode(enabled) {
        this.options.debug = enabled;
    }
    
     /* Set Request Headers */
    setRequestHeaders(headers) {
        this.options.headers = headers;
    }

    /* Custom Callbacks */
    setRequestCallback(callback) {
        this.options.requestCallback = callback;
    }
    
    setResponseCallback(callback) {
        this.options.responseCallback = callback;
    }
    
    /* Authentication */
    setAuthenticationToken(token) {
        this.options.authToken = token;
    }    
    
    /* Caching methods */
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

    async calculateTransactionFee(tx) {
        // Use the fee calculation logic from the SPHINXFees namespace
        return this.feesNamespace.calculateTransactionFee(tx);
    }

    async processTransactions(transactions) {
        // Use the processTransactions logic from the SPHINXFees namespace
        this.feesNamespace.processTransactions(transactions);
    }

    // Calculate gas fees using SPX tokens
    calculateGasFee(gasAmount) {
        const gasPriceInSPX = gasAmount * this.options.gasPrice * this.options.spxGasMultiplier;
        return gasPriceInSPX;
    }

    // Set SPX gas multiplier
    setSpxGasMultiplier(multiplier) {
        if (typeof multiplier !== 'number' || multiplier <= 0) {
            throw new Error('SPX gas multiplier must be a positive number');
        }
        this.options.spxGasMultiplier = multiplier;
        return this; // Allow chaining
    }

    // Chaining and configuration method
    static configure(endpoint) {
        return new Sphinx(endpoint);
    }
}

module.exports = Sphinx;