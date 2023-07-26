Layer 2: Non Interactive Protocols
==================================

The second layer of libscapi currently includes different symmetric and asymmetric encryption schemes. In the future this layer will also include message authentication codes and digital signatures. It heavily uses the primitives of the first layer to perform internal operations. For example, the ElGamal encryption scheme uses DlogGroup.

.. toctree::
   :maxdepth: 2

   mid_layer/mac
   mid_layer/symmetric_enc
   mid_layer/asymmetric_enc
