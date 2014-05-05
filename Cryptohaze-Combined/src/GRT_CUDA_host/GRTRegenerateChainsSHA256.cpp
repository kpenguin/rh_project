#include "GRT_CUDA_host/GRTRegenerateChainsSHA256.h"



// Call the constructor of GRTRegenerateChains with len 32
GRTRegenerateChainsSHA256::GRTRegenerateChainsSHA256() : GRTRegenerateChains(32) {
    return;
}

void GRTRegenerateChainsSHA256::copyDataToConstant(GRTRegenerateThreadRunData *data) {
    char hostCharset[512]; // The 512 byte array copied to the GPU
    int i;
    char** hostCharset2D; // The 16x256 array of characters
    uint32_t charsetLength;
    char *CharsetLengths;
    uint32_t numberThreads;

    hostCharset2D = this->TableHeader->getCharset();
    CharsetLengths = this->TableHeader->getCharsetLengths();
    numberThreads = this->ThreadData[data->threadID].CUDABlocks *
            this->ThreadData[data->threadID].CUDAThreads;

    charsetLength = CharsetLengths[0];

    // debug
    printf("Charset length: %d\n", charsetLength);

    for (i = 0; i < 512; i++) {
        hostCharset[i] = hostCharset2D[0][i % charsetLength];
    }


    copySHA256RegenerateDataToConstant(hostCharset, charsetLength,
        this->TableHeader->getChainLength(), this->TableHeader->getTableIndex(),
        numberThreads, this->hostConstantBitmap, this->NumberOfHashes);
    return;

}

void GRTRegenerateChainsSHA256::setNumberOfChainsToRegen(uint32_t numberOfChainsToRegen) {
    setSHA256RegenerateNumberOfChains(numberOfChainsToRegen);
}


void GRTRegenerateChainsSHA256::Launch_CUDA_Kernel(unsigned char *InitialPasswordArray, unsigned char *FoundPasswordArray,
        unsigned char *DeviceHashArray, UINT4 PasswordSpaceOffset, UINT4 StartChainIndex,
        UINT4 StepsToRun, UINT4 charset_offset, unsigned char *successArray, GRTRegenerateThreadRunData *data) {

    // Launch the actual kernel function
    LaunchSHA256RegenerateKernel(this->PasswordLength, this->ThreadData[data->threadID].CUDABlocks,
            this->ThreadData[data->threadID].CUDAThreads, InitialPasswordArray, FoundPasswordArray,
        DeviceHashArray, PasswordSpaceOffset, StartChainIndex,
        StepsToRun, charset_offset, successArray, this->NumberOfHashes);
}
