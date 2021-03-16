# recovery mechanism

NeoID uses the recovery mechanism to assign others as the coordinator, which means they can act as the issuer in the network. The coordinator can be set to one or more. 

The recovery mechanism somehow serves as the Committee in Neo core. It can add and remove public keys (coordinators) to the NeoID, and update the recovery settings. The operation should provide a valid digital signature that conforms to the control logic.

>*The recovery mechanism is desired for the back up of the issuer. For Credential, recovery can be done through off-chain methods, such as backup and cloud hosting. Credential recovery is beyond the scope of this article.*

## Data changed

There should be the data structure to store the recovery information.

The recovery consists of two parts, namely, the threshold and the members. Members stores all the public keys in the recovery, and the threshold is used to specify the minimum signatures to verify the message，, as shown below：

```json
  {
    "threshold": m,
    "members": [publickey1, publickey2, ... , publickeyn]
  }
```

Here is the example of three members：

```
 "recovery": {
    "threshold": 2,
    "members": [
        "did:neoid:main:81210f2127603ae7e910e452e4a140ee4e713527",
        "did:neoid:main:7u8ehd0603ae7e910e452e4a140dgetsj7352de6",
        "did:neoid:main:7u8ehd0603ae7e910e452e4a140dgetsj7352de6"
  }
```

#### Set recovery

setRecovery

parameters:

Number |  Type   | Desc
----|---------|-------
 0  |  BigInteger  | threshold
 1  |  ECPoint[]  | the public keys in the recovery list
 2  |  BigInteger    | the index of the signature
 3  |  byte[]    | the signed message |
 4  |  byte[] | the signature for initializing

Only the owner of the issuer contract can initiate the recovery list.



#### Update recovery

updateRecovery

parameters:

Number |  Type   | Desc
----|---------|-------
 0  |  BigInteger  | threshold
 1  |  ECPoint[]  | the public keys in the recovery list
 2  |  BigInteger[]    | indexes of signatures for updating
 3  |  byte[]    | the signed message |
 4  |  byte[][] | signatures for updating

To set the recovery successfullt, there should at least threshold number of signatures of the members in the `current` recovery list on the message. And the order of the signature is specified by the second parameter.

#### Add a public key by recovery

addKeyByRecovery

parameters:

Number |  Type   | Desc
----|---------|-------
 0  |  ECPoint  | the public key to be added
 1  |  BigInteger[]  | indexes of signatures  of the public keys in the current recovery list
 2  |  byte[]  | the signed message
 3  |  byte[][] | signatures of the public keys in the current recovery list

To add the public key successfullt, there should at least threshold number of signatures of the members in the `current` recovery list on the message. And the order of the signature is specified by the second parameter.

#### Remove a public key by recovery

removeKeyByRecovery

parameters:

Number |  Type   | Desc
----|---------|-------
 0  |  ECPoint  | the public key to be removed
 1  |  BigInteger[]  | indexes of signatures  of the public keys in the current recovery list
 2  |  byte[]  | the signed message
 3  |  byte[][] | signatures of the public keys in the current recovery list

To remove the public key successfullt, there should at least threshold number of signatures of the members in the `current` recovery list on the message. And the order of the signature is specified by the second parameter.