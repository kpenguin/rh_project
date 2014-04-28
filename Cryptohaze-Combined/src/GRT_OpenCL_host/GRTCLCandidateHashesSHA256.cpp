/*
Cryptohaze GPU Rainbow Tables
Copyright (C) 2011  Bitweasil (http://www.cryptohaze.com/)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "GRT_OpenCL_host/GRTCLCandidateHashesSHA256.h"
#include <stdio.h>


GRTCLCandidateHashesSHA256::GRTCLCandidateHashesSHA256() : GRTCLCandidateHashes(20) {
    //printf("GRTCLCandidateHashesSHA256::GRTCLCandidateHashesSHA256()\n");
}

std::vector<std::string> GRTCLCandidateHashesSHA256::getHashFileName() {
    std::string HashFileName;
    std::vector<std::string> filesToReturn;

    HashFileName = "kernels/GRT_OpenCL_Common.h";
    filesToReturn.push_back(HashFileName);
    HashFileName = "kernels/GRT_OpenCL_SHA256.h";
    filesToReturn.push_back(HashFileName);
    HashFileName = "kernels/GRTCLCandidateHashesSHA256.cl";
    filesToReturn.push_back(HashFileName);

    return filesToReturn;
}

std::string GRTCLCandidateHashesSHA256::getHashKernelName() {
    std::string HashKernelName;

    HashKernelName = "CandidateHashSHA256AMD";

    return HashKernelName;
}
