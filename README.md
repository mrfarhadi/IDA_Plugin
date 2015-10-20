# IDA_Plugin

The script can be run in two ways: 

1- Open IDA with a binary file and press "ALT+F7", then choose the script and click submit, IDA also asks for a text file for output, you may choose an empty text file but the output will not be written there.  

2- Use IDA command line as following:
idaq -A -S[scriptPath] [binaryPath] 

(For more info on IDA command line switches: https://www.hex-rays.com/products/ida/support/idadoc/417.shtml)

The script will generate 3 files: 

1. BinayFileName.text.asm --> The ordinary asm file
2. BinaryFileName.text.info --> Script output file
3. BinaryFileName.text.asmplus --> assembly code file + segment information to be used for address mapping

The first file is the ordinary assembly file genereated by IDA Pro.
The second file is the script output file.
The last one is an assembly code file with assembly instruction segment information to be used for address mapping.


For each file, this script extracts all functions and prints the CG adjacency matrix.
Also, For each function, all basic blocks are extracted as well as CFG adjacency matrices.

The script output structure is: 

Function Name (First Function):

   Function ID
   ASM FIle Starting Address
   ASM File Ending Address
   Binary File Starting Address
   Binary File Ending Address
   Caller Functions

   Basic Block
   BB_ID
   ASM FIle Starting Address
   ASM File Ending Address
   Binary File Starting Address
   Binary File Ending Address
   Basic Block Successors 
   . 
   . 
   .
   (ALL BASIC BLOCKS)

   CFG Adjacency Matrix



Function Name: (Next Function)
.
.
.
 CG adjacency Matrix
