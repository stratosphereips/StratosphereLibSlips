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
*    processor.h is written by
*	        Sachin Vernekar (savernek@cisco.com)
*               Kshitij Gupta (kshgupta@cisco.com)
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
#ifndef PROCESSOR_H
#define PROCESSOR_H

#include <queue>
#include <memory>
#include "markov_models_1.h"

namespace Slips
{
extern MarkovModelsDetection __markov_models__;
extern std::map<std::string, std::shared_ptr<Tuple>> tuples;
extern int verbose;
extern int slot_width;
extern int amount;
extern bool dontdetect;
extern bool only_detections;
// A class to process the flows
class Processor
{
private:
    std::queue<std::string> que;
    Datetime slot_starttime;
    Datetime slot_endtime;
    std::map<std::string, std::shared_ptr<Tuple>*> tuples_in_this_time_slot;

public:
    std::shared_ptr<Tuple> *get_tuple(std::string tuple4);
    void process_out_of_time_slot(std::vector<std::string> column_values);
    void detect(std::shared_ptr<Tuple> *tuple) throw(int);
    bool start() throw(int);
    void addToQueue(std::string line);
    bool checkQueueEmpty();
    std::string getNext();
    void removeNext();
};
}
#endif
