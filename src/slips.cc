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
*    slips.cc is written by
*	 	Sachin Vernekar (savernek@cisco.com)
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

#include <fstream>
#include <iostream>
#include <regex>
#include <dirent.h>
#include "slips.h"

using std::cerr;
using std::endl;

namespace Slips
{

extern bool match;
extern char matchedBotnetModel[512];

std::unique_ptr<Processor> processor;
std::string path_to_netflows = "Read from stdin";
int verbose = 1;
int slot_width = 5;
int amount = -1;
bool dontdetect = false;
int num_models;
bool models_read = false;
//TO-DO [savernek]: This value is hard-coded for now, need to ascertain the need for it.
bool only_detections = true;

void slips_init(const char* pathToSlipsConfFile)
{
    std::string currLine = "";
    std::string models_dir = "models/";
    bool models_parsed = false;
    bool netflows_parsed = false;
    bool verbosity_parsed = false;
    bool width_parsed = false;
    bool amount_parsed = false;
    bool dontdetect_parsed = false;

    std::ifstream infile;
    infile.open(pathToSlipsConfFile);

    if(!infile.is_open())
    {
        cerr << "ERROR: Cannot open configuration file, hence assuming default configurations and reading netflows from STDIN"<<endl;
    }
    else
    {
        while(!infile.eof())
        {
            getline(infile,currLine);
            if(currLine.compare(0,1,"#") == 0)
            {
                continue;
            }
            const std::string& input = currLine;
            std::regex rgx1("(models:)(\\s*)(.*)");
            std::regex rgx2("(netflows:)(\\s*)(.*)");
            std::regex rgx3("(verbosity:)(\\s*)(.*)");
            std::regex rgx4("(width:)(\\s*)(.*)");
            std::regex rgx5("(amount:)(\\s*)(.*)");
            std::regex rgx6("(dontdetect:)(\\s*)(.*)");
            std::smatch match;
            if (!models_parsed && std::regex_search(input.begin(), input.end(), match, rgx1))
            {
                models_parsed = true;
                models_dir = match[3].str().c_str();
                continue;
            }
            if (!netflows_parsed && std::regex_search(input.begin(), input.end(), match, rgx2))
            {
                netflows_parsed = true;
                path_to_netflows = match[3].str().c_str();
                continue;
            }
            if (!verbosity_parsed && std::regex_search(input.begin(), input.end(), match, rgx3))
            {
                verbosity_parsed = true;
                try
                {
                    verbose = std::stoi(match[3].str().c_str());
                }
                catch (const std::invalid_argument& ia)
	        {
                    cerr <<"WARNING: Error parsing verbosity, hence setting it to default: "<< verbose <<endl;
                }
                continue;
            }
            if (!width_parsed && std::regex_search(input.begin(), input.end(), match, rgx4))
            {
                width_parsed = true;
                try
                {
                     slot_width = std::stoi(match[3].str().c_str());
                }
                catch (const std::invalid_argument& ia)
                {
                    cerr <<"WARNING: Error parsing width, hence setting it to default: "<< slot_width <<endl;
                }
                continue;
            }
            if (!amount_parsed && std::regex_search(input.begin(), input.end(), match, rgx5))
            {
                amount_parsed = true;
                try
                {
                    amount = std::stoi(match[3].str().c_str());
                }
                catch (const std::invalid_argument& ia)
                {
                    cerr <<"WARNING: Error parsing amount, hence setting it to default: "<< amount <<endl;
                }
                continue;
            }
            if (!dontdetect_parsed && std::regex_search(input.begin(), input.end(), match, rgx6))
            {
                dontdetect_parsed = true;
                dontdetect = (match[3].str().compare("true") == 0);
                continue;
            }
        }
    }

    std::vector<std::string> onlyfiles;
    DIR *dp;
    struct dirent *dirp;
    if ((dp = opendir(models_dir.c_str())) == NULL)
    {
        cerr << "ERROR: models directory could not be read" <<endl;
        models_read = false;
        return;
    }
    while ((dirp = readdir(dp)) != NULL)
    {
        if ((0 == strcmp(dirp->d_name, "."))
                || (0 == strcmp(dirp->d_name, "..")))
            continue;
        onlyfiles.push_back(dirp->d_name);
    }
    (void) closedir(dp);
    for (size_t i = 0; i < onlyfiles.size(); i++)
    {
        __markov_models__.set_model_to_detect(
            (models_dir+onlyfiles[i]).c_str());
    }
    num_models = onlyfiles.size();
    if(num_models == 0)
    {
        cerr << "ERROR: There are no models in models directory" <<endl;
        return;
    }
    models_read = true;
}

char* slips_detect(std::string line)
{
    if(line.empty())
        return NULL;

    processor->addToQueue(line);
    processor->start();
    if(match)
    {
        match = 0;
        return matchedBotnetModel;
    }
    return NULL;
}

}
