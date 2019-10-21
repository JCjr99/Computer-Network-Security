#File using the line-count.sh file as a base
#File created by Jacob Cooper(H00251723) At Heriot- Watt for the Symmetric
#Encryption coursework of the Computer Network Security Course (F20CN)
#this file performs brute force know-plaintext attack by taking in a list of
#possible words, the cipher output and the original plaintext that was encrypted.
#It then loops through the possible words(printing out the current word and its
#number in the list as we go) , encrypts the plain text with this
#word as the key and then compares the enciphered file to the cipher given and
#if it matches then the word currently being read must be the key and so it
#prints out this key. 
#This file is run as:
#./known-plaintext-attack.ssh <dictitonary> <cipher> <plaintext>




# Link filedescriptor 10 with stdin
exec 10<&0


#Used to make the first argument readaable in the while loop further down
exec < $1
#intiialisation of arguments
#store the first argument in value 'dictionary', this is the list of possible
#words which could be the key
dictionary=$1
#store the second argument in 'ciper',this is the enciphered version of 'plain'
#that used some word from the 'dictionary' as a key
cipher=$2
#store third argument in 'plain', this will be the plain text that we know was
#used to generate the cipher
plain=$3

#Initialisation of a count to keep track of how far we are in the dictionary
let count=0

# this while loop iterates over all lines of the 'dictionary' file
while read LINE
do
    # increase line counter
    ((count++))
    #this encrypts the plain text using each word from the 'dictionary' file as
    #a key and then puts that output to a file called 'out.txt' , we know that
    #there is no salt and the encryption used was aes-128
    openssl enc -aes-128-cbc -nosalt -e -in $plain -out out.txt -pass pass:$LINE
    #print out what line we are on
    echo $count
    #print out what word we are checking
    echo "checking ${LINE}"
    #compares the encryption of the current word (stored in out.txt) with the
    #known cipher text
    if cmp -s $cipher out.txt; then
      #if they do match then we have found our key and can break the loop
      echo "Key found: ${LINE}"
      break
    fi
done

# restore stdin from filedescriptor 10
# and close filedescriptor 10
exec 0<&10 10<&-
