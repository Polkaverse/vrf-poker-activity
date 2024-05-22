# Activity: Infinite deck poker using VRFs

As we learnt in class, VRFs are a way of providing private randomness that can later be publicly revealed.

A card game also has randomness, for instance, drawing a random card, which can be kept a secret until the card is played.

We can use a VRF output mod 52 to determine a card.

## Challenge

Your task is to create a poker game or a simplification of one that uses VRFs to determine a players' card.

### Possible simplifications

Card-less poker - There are no hands.
The player with the highest VRF revealed at the end should win the game but with the usual poker bidding rules.

Or we can simplify bidding etc.
