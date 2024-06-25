# Implement of 128-EEA3 & 128-EIA3
This repo offers simple implements and test code of ZUC algorithm, 128-EEA3 algo and 128-EIA3 algo, 
where ZUC algo generates the key stream to help finishing EEA3 & EIA3, 
EEA3 algo transfer the message to the ciphertext 
and EIA3 algo computes MAC then check the interity of the message or ciphertext.

# About source code
The core algo code refs the official doc. But EEA3 got some improvement at handing the input massage whose size is not full byte(Length param can not be divisible by 8). See details at [The New LTE Cryptographic Algorithms EEA3 and EIA3Verification, Implementation and Analytical Evaluation](https://readpaper.com/pdf-annotate/note?pdfId=4546071540415488001&noteId=2357874282761130752)

# About test code
I add all the test dataset from the doc and all of them can pass

# Run
```bash
make
./bin/test/test_zuc
./bin/test/test_eea3
./bin/test/test_eia3
```