/**
*
*    SLIPS - Stratosphere Linux IPS
*
*    Author: Sebastian Garcia.
*    Email : eldraco@gmail.com , sebastian.garcia@agents.fel.cvut.cz
*
*    Stratosphere IPS, a behavioral-based intrusion detection and prevention
*    system that uses machine learning algorithms to detect malicious behaviors
*    Website : https://stratosphereips.org/
*
*    libSlips - CPP Implementation of Stratosphere IPS
*    testslips.cc is written by
*		Sachin Vernekar (savernek@cisco.com)
*		Kshitij Gupta (kshgupta@cisco.com)
*
*    Copyright (C) 2016, Cisco Systems Inc.
*
*    This library is free software; you can redistribute it and/or
*    modify it under the terms of the GNU Lesser General Public
*    License as published by the Free Software Foundation; either
*    version 2.1 of the License, or (at your option) any later version.
*
*    This library is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
*    Lesser General Public License for more details.
*
*    You should have received a copy of the GNU Lesser General Public
*    License along with this library; if not, write to the Free Software
*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*
**/
#include <iostream>
#include <fstream>
#include "slips.h"

extern bool match;
extern char matchedBotnetModel[512];

using std::cout;
using std::endl;
using std::cerr;

int main(int argc, char* argv[])
{
    if ( argc != 2 ) // argc should be 2 for correct execution
        cerr<<"usage: slips path-to-slips.conf \n";
    else
    {
        std::string line;
        char* slipsRes=NULL;
        bool slips = 0;
        Slips::slips_init(argv[1]);
        if(!Slips::models_read)
        {
            cerr<<"ERROR: Unable to open models directory and read models. Exiting!"<<endl;
            return 0;
        }
        cout<<"Read "<<Slips::num_models<<" models"<<endl;
        std::string currLine = "";
        std::ifstream infile;
        Slips::processor.reset(new Slips::Processor());
        cout<<"Processing Flows ..."<<endl;
        if(Slips::path_to_netflows.compare("Read from stdin") != 0)
        {
            infile.open(Slips::path_to_netflows);
            if(!infile.is_open())
            {
                cerr<<"ERROR: Unable to open netflow file. Please correct the path. If reading from stdin, then comment out netflows from the slips.conf file."<<endl;
                return 0;
            }
            while(!infile.eof())
            {
                getline(infile,currLine);
                try
                {
                    slipsRes = Slips::slips_detect(currLine);
                    if(slipsRes)
                    {
                        slips=1;
                    }
                }
                catch(...)
                {
                    cerr << "ERROR: Error in main" <<endl;
                }
            }
            infile.close();
        }
        else
        {
            cout << "Reading from STDIN" <<endl;
            while(getline(std::cin,line))
            {
                slipsRes = Slips::slips_detect(line);
                if(slipsRes)
                {
                    slips=1;
                }
            }
        }
    }
    return 0;
}
