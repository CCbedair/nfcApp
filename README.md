###### CS-E4300 Network security, 2018


# Project Report: Ticket Application by Group _19_

_Ahmed Beder 727176, Mariana Farias 726180, Shamim Biswas 727228_

## Overview

This Ultralight Ticketing Application will allow users to:
 1. Buy a ticket with 5 valid rides and expiration date of midnight of the day first use of the ticket.
 2. Top off tickets with extra rides without losing already available rides
   
The intended security properties include:
  1. Tampering prevention for values on the card, like valid rides and expiration date.
  2. Tearing protection.
  3. Key Diversification.

When using the card, the user will be able to select to top off the tickets or use tickets from the card on the reader's menu. When using a ticket, the user will tap his card and be presented with the remaining number of rides and the expiration date of the ticket.
When topping off, the user will choose the number of extra rides and then tab his card and be presented with the remaining number of rides and the expiration date of the ticket.


## Ticket application structure
 This table reflects the data structure of the card application.

<table>
  <tr>
    <td colspan="2"><b><center> Page address </center></b></td>
    <td colspan="4"><b><center> Byte number </center></b></td>
  </tr>
  <tr>
    <td><b><center> Decimal </center></b></td>
    <td><b><center> Hex </center></b></td>
    <td><b><center> 0 </center></b></td>
    <td><b><center> 1 </center></b></td>
    <td><b><center> 2 </center></b></td>
    <td><b><center> 3 </center></b></td>
  </tr>

  <tr>
    <td> 0 </td>
    <td> 00h </td>
    <td colspan="4"> serial number </td>
  </tr>

  <tr>
    <td> 1 </td>
    <td> 01h </td>
    <td colspan="4"> serial number </td>
  </tr>

  <tr>
    <td> 2 </td>
    <td> 02h </td>
    <td> serial number </td>
    <td> internal </td>
    <td> lock bytes </td>
    <td> lock bytes </td>
  </tr>

  <tr>
    <td> 4 </td>
    <td> 04h </td>
    <td> user memory </td>
    <td> user memory </td>
    <td> user memory </td>
    <td> user memory </td>
  </tr>

  <tr>
    <td> ... </td>
    <td> ... </td>
    <td> </td>
    <td> </td>
    <td> </td>
    <td> </td>
  </tr>

 <tr>
    <td> 20 </td>
    <td> 14h </td>
    <td colspan="2"> valid rides [even]</td>
    <td colspan="2"> expiration [even]</td>
  </tr>

  <tr>
    <td> 21 </td>
    <td> 15h </td>
    <td colspan="4"> MAC [even]</td>
  </tr> 

  <tr>
    <td> ... </td>
    <td> ... </td>
    <td> </td>
    <td> </td>
    <td> </td>
    <td> </td>
  </tr>

  <tr>
    <td> 30 </td>
    <td> 1Eh </td>
    <td colspan="2"> valid rides [odd]</td>
    <td colspan="2"> expiration [odd]</td>
  </tr>

  <tr>
    <td> 31 </td>
    <td> 1Fh </td>
    <td colspan="4"> MAC [odd]</td>
  </tr>

  <tr>
    <td> ... </td>
    <td> ... </td>
    <td> </td>
    <td> </td>
    <td> </td>
    <td> </td>
  </tr>


  <tr>
    <td> 40 </td>
    <td> 28h </td>
    <td colspan="2"> lock bytes </td>
    <td> - </td>
    <td> - </td>
  </tr>

  <tr>
    <td> 41 </td>
    <td> 29h </td>
    <td colspan="2"> Counter c </td>
    <td> - </td>
    <td> - </td>
  </tr>

  <tr>
    <td> 42 </td>
    <td> 2Ah </td>
    <td colspan="4"> authentication configuration </td>
  </tr>

  <tr>
    <td> 43 </td>
    <td> 2Bh </td>
<td colspan="4"> authentication configuration </td>
  </tr>

  <tr>
    <td> 44 to 47 </td>
    <td> 2Ch to 2Fh </td>
<td colspan="4"> authentication key </td>
  </tr>
</table>

**Counter c:** We make use of the Ultralight 16-bit counter to account for the number of operations already executed on the card. Whenever we conclude an issue or use operation, we increment the counter. Using this variable, in tandem with an even/odd pages for reading and writing schemes works as a control technique in case of tearing.  
**Valid Rides:** Keeps track of the number of rides left in the card.  
**Expiration:** The number of days from the UNIX Epoch.   
**Mac(Valid Rides + expiration + c):** A Mac of all values present in the card truncated to fit one page of memory. This variable guarantees the integrity of the data present on the card.  

## Key management

The authentication key is changed and stored on the card during the issuing the card for the first time. Each card has a unique authentication key and the keys are stored in a hashed file on the reader as key-value pairs where the key is the uuid of the card and the value is the authentication key.

As for keys used in the calculation of MACs, we use the unique identifiers all cards have on their first 7 bytes concatenated with a secret known to the readers.  

To imporve this scheme, we can later on switch to storing the keys on a server and fetching only the authentication keys and reader secret of that specific card.

## Implementation

**Issue**  
The following is a pseudo-code representation of our algorithm:  
```
Check counter c: 
  if it is even: read from even pages/write on odd pages  
  else: read from odd pages/write on even pages

Read valid rides
Read exp

Calculate test MAC(valid rides + exp + c)

Read current MAC
if (current MAC = test MAC):
  if (exp = currentDate):
    valid rides += 5 and exp = exp
  else:
    valid rides = 5 and exp = empty
else:
  valid rides = 5
  exp = empty

current MAC = MAC(valid rides + exp + c+1)
c +=1
```  
The issue code is present in the _Ticket.java_ class, inside the issue method. In order to assign a card, a reader starts by sending an authentication request with the authentication key both the reader and the card know. This process is well documented in the Ultralight C data sheet.  
Afterwards, the reader will check the value on the counter. If it is an even value, the values will be read from the pages assigned as even (20 and 21) and write the new values to the pages assigned as odd (30 and 31). If it is an odd value, the reads will be done from the odd pages and the writes will be done to the even pages.  
Then we will read from the card its current valid rides and its expiration date. A new MAC will be calculated with this values using a key generated by the concatenation of the card ID and a common secret to all readers. This MAC will then be compared to the MAC present in the card. If they don't match, either the Card has been tampered with or the card is new and has never had a MAC calculated. In either of these cases, we will set the number of valid rides to five and delete the expiration date. If the MAC does match, we will check if it is still valid for the day. If that is the case, we add 5 more rides to the total number of valid rides and keep the expiration date as its current value. Otherwise, we set the number of valid rides to 5 and delete the expiry date.  
Afterwards, we calculate a new MAC with the new values and the value of the counter incremented and set it. Finally, we increment the counter. 
   
**Use**  
The following is a pseudo-code representation of our algorithm:  
```
Check counter c: 
  if it is even: read from even pages/write on odd pages  
  else: read from odd pages/write on even pages

Read valid rides
Read exp

Calculate test MAC(valid rides + exp + c)

Read current MAC
if (current MAC != test MAC):
  REJECT
if exp = empty:
  exp = current date
else:
  if (exp != current date): 
    REJECT
  else: exp = exp
  
if (valid rides = 0):
  REJECT
else: 
  valid rides -= 1

current MAC = MAC(valid rides + exp + c+1)
c +=1

```  
The use code is present in the _Ticket.java_ class, inside the use method. In order to use a card, a reader starts by sending an authentication request with the authentication key both the reader and the card know. This process is well documented in the Ultralight C data sheet.
Afterwards, the reader will check the value on the counter. If it is an even value, the values will be read from the pages assigned as even (20 and 21) and write the new values to the pages assigned as odd (30 and 31). If it is an odd value, the reads will be done from the odd pages and the writes will be done to the even pages.  
Then we will read from the card its current valid rides and its expiration date. A new MAC will be calculated with this values using a key generated by the concatenation of the card ID and a common secret to all readers. This MAC will then be compared to the MAC present in the card. If this values don't match, someone has tampered with the card and it will be rejected by the reader. Otherwise, the reader will check if the expiration date has already been set. If it hasn't, it means it is the first time we are using the card after issuing and therefore, we will set the expiration date to the next midnight. If it has been set, we check that the card is still valid. If it isn't, the card will be rejected.  
If the card is not expired, we check if it still has rides. If it doesn't, we will reject the card. Otherwise, we decrement the number of rides it has left.  
Afterwards, we calculate a new MAC with the current values and the value of Counter incremented set the new MAC. Finally, we increment the value of c.  


## Evaluation

### Security evaluation

* **Security Achieved**:
  * ***Rollback Prevention***
    An attacker may attempt to write back old data to the same card, including old MACs that would enable the attacker to restore tickets after using it.
    This is prevented in the architecture by including the counter in the MAC stored. Since the counter can never be decremented the MAC check should not pass unless the card has not been tampered with.
  * ***Man In the Middle Prevention***
    An attacker may send commands to modify the card contents after authentication has been established.
    This is prevented in the architecutre by including a MAC for the rides and expiration date values and stroing that on the card.
  * ***System Failure due to Leaked Key***
    This is guranteed by making secret key for each card, which includes a master key and that card's UUID.
  * ***Tearing Protection***
    Tearing can happen if the user pulls the card away from the reader during writing, in particular when there are multiple page writing operation.
    This is prevented in the architecture by using the counter as a transaction control value and keeping two sets of the data, even and odd.
    When the counter is even, the reader will read from pages 20, 21 and write to 30,31 and when the counter is odd, the reader will read from pages 30,31 and write to 20,21. Only when all writing operations have been commited will the counter be updated.

* **Known Weaknesses**
  * ***Pass-back***
  An attacker can use the card, and pass back to another person to also use the same card. Even though the valid rides is decremented each time, this would allow multiple people to use only one card.
  This problem could be mitigated by adding a timestamp when using the ticket and blocking of the use for the ticket for a resonable time with respect to that timestamp.
  * ***No On-the-fly modifications to data structures***
  This can be mitigated to some extent by adding a version tag to the card and checking that tag to identify which protocol to use. This depends on the updating of the datastructure as some fields like the counter may not be suitable to use for a different function.

### Reliability and deployablity

How reliability and deployability were considered in the ticket design.
* **Reliabiltiy**:
  When designing the the ticketing application, we wanted to guarantee that the user will have seamless interaction with the ticket to use his rides. We insured that there will be no errors due to tearing by using even/odd writing schemes and that there are as few writing transactions as possible so that the transaction is seamless.
  Furthermore, in the intial design all the required keys are present on the reader so there will be no failures or slowness due to network errors.
  This can be mitigated however, even when using an online server for keys by implementing offline authentication with limited number of times.

* **Deployability**:
The reader consists of a simple android application so it can easily be deployed to any phone.

## Final notes
### Feedback
We found the _Advice on NFC ticket design on MIFARE Ultralight C_ file very useful.  
We consider that for the duration of the week, the weekly assignments are a bit hard to solve.  
### Open Questions
* Was there any way to implement the use operation without multiple writes?  
