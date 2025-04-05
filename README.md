# BROP

<p align="center">
  A python module that aims to help the exploitation of Blind ROP techniques 
  <br>
  <br>
</p>

## Abstract

BROP (Blind ROP) was a technique found by Andrew Bittau from Stanford in 2014.

- [Original paper](https://www.scs.stanford.edu/brop/bittau-brop.pdf)
- [Slides](https://www.scs.stanford.edu/brop/bittau-brop-slides.pdf)

Most servers like nginx, Apache, MySQL, forks then communicates with the client. This means canary and addresses stay the same even if there is ASLR and PIE. So we can use some educated brute force to leak information and subsequently craft a working exploit.

## BROPPER

<p align="center">
  An automatic Blind ROP exploitation python tool created by https://github.com/Hakumarachi/Bropper
  <br>
  <br>
</p>
