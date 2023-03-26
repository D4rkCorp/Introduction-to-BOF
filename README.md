# Introduction-to-BOF

## Part-1
> We started with the definition of BOFs, and the requirement is straightforward and gives an advanced and easy solution to expand our Post-Exploitation techniques and behaviour. Then we talked about why we need the BOFs and went through the technical details by discussing the structure and sections of Beacon Object Files; This includes the function convention and an alternate convention, which means how we are supposed to declare all the Win32 functions, and using it in a BOF. And why we need this type of convention in the BOF file. Next, we moved to Aggressor Scripting and scripts; we discussed the basics of scripting with handling user arguments and loading shellcodes to our BOFs. Once all possible requirements were completed, we created two BOFs: process injection and Patching Etw in the remote process.

### Source Code

1.  [InjectShellCode](InjectShellCode/src/InjectShellCode.c)
2.  [EtwPatch](EtwPatch/src/EtwPatch.c)

