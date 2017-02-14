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
*    processor.cc is written by
*               Sachin Vernekar (savernek@cisco.com)
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
#include <iostream>
#include <string.h>
#include <list>
#include "processor.h"
#include "constants.h"

using std::cerr;
using std::cout;
using std::endl;

namespace Slips
{
bool match=0;
char matchedBotnetModel[512];

std::map<std::string, std::shared_ptr<Tuple>> tuples;
MarkovModelsDetection __markov_models__ ;

std::shared_ptr<Tuple>* Processor::get_tuple(std::string received_tuple)
{
    // Get the values and return the correct tuple for them
    if (tuples.find(received_tuple) != tuples.end())
    {
        // We already have this connection
        return &tuples[received_tuple];
    }
    // First time for this connection
    tuples[received_tuple] =  std::shared_ptr<Tuple>(new Tuple(received_tuple));
    tuples[received_tuple]->set_verbose(verbose);
    return &tuples[received_tuple];
}

void Processor::process_out_of_time_slot(std::vector<std::string> column_values)
{
    // Process the tuples when we are out of the time slot
    // Outside the slot
    if(verbose) {
        cout << "Slot Started: "<< slot_starttime.get_time_string() <<", finished: "<< slot_endtime.get_time_string() << ". (" << tuples_in_this_time_slot.size() << " connections)" <<endl;
        for (std::map<std::string, std::shared_ptr<Tuple>>::iterator it = tuples.begin(); it != tuples.end(); ++it) {
            // We cut the strings of letters regardless of it being detected before.
            if((it->second)->amount_of_flows > amount && (it->second)->should_be_printed) {
                cout << (it->second)->print_tuple_detected() <<endl;
                if((it->second)->should_be_printed) {
                    (it->second)->dont_print();
                }
            }
        }
    }
    // After each timeslot finishes forget the tuples that are too big. This is useful when a tuple has a very very long state that is not so useful to us. Later we forget it when we detect it or after a long time.
    std::list<std::string> ids_to_delete;
    for (std::map<std::string, std::shared_ptr<Tuple>>::iterator it = tuples.begin(); it != tuples.end(); ++it)
    {
        // We cut the strings of letters regardless of it being detected before.
        if((it->second)->amount_of_flows > 100)
        {
            if (verbose > 3)
                cout << "Delete all the letters because there were more than 100 and it was detected. Start again with this tuple." <<endl;
            ids_to_delete.push_back(it->first);
        }
    }
    // Actually delete them
    for (std::list<std::string>::const_iterator ci = ids_to_delete.begin(); ci != ids_to_delete.end(); ++ci)
        tuples.erase(*ci);
    // Move the time slot
    slot_starttime = Datetime(get_time_data(column_values[0]));
    slot_endtime = slot_starttime;
    slot_endtime.update_time(slot_width * 60);

    // Put the last flow received in the next slot, because it overcame the threshold and it was not processed
    std::string received_tuple = column_values[3] + '-' + column_values[6] + '-' + column_values[7] + '-' + column_values[2];
    std::shared_ptr<Tuple> *tuple = get_tuple(received_tuple);
    (*tuple)->add_new_flow(column_values);
    // Detect the first flow of the future timeslow
    detect(tuple);
    tuples_in_this_time_slot.clear();
}

void Processor::detect(std::shared_ptr<Tuple> *tuple) throw(int)
{
    // Detect behaviours
    try
    {
        if(!dontdetect)
        {
            DetectionInfo detection_info = __markov_models__.detect(**tuple, verbose);
            if(detection_info.matched)
            {
                // Set the detection label
                (*tuple)->set_detected_label(detection_info.label);
                std::string matchline = (*tuple)->get_detected_label();
                match = 1;
                memset(matchedBotnetModel,0,512);
                strncpy(matchedBotnetModel,matchline.c_str(),511);
                if(verbose > 5)
                    cout << ((*tuple)->datetime).get_time_string() << " Last Flow detected with " << (*tuple)->get_detected_label() << endl;
                //For functional test
                if(!verbose)
                    cout << ((*tuple)->datetime).get_time_string() << " Last Flow detected with " << (*tuple)->get_detected_label() << endl;

            }
            else if(!detection_info.matched && only_detections)
            {
                // Note detected by any reason. No model matching but also the sate len is too short.
                (*tuple)->unset_detected_label();
                if(verbose > 5)
                    cout << "Last flow: Not detected"<<endl;
                (*tuple)->dont_print();
            }
        }
    }
    catch(std::exception &e)
    {
        cerr << "ERROR: Problem with detect()\n" << e.what() <<endl;
        throw(ERROR_UNEXPECTED_ERROR);
    }
    catch(...)
    {
        cerr << "ERROR: Problem with detect()" <<endl;
        throw(ERROR_UNEXPECTED_ERROR);
    }
}

bool Processor::start() throw(int)
{
    try
    {
        std::vector<std::string> column_values;
        std::string line;
        if (checkQueueEmpty())
        {
            return false;
        }
        else
        {
            line = getNext();
            removeNext();
        }
        if ("stop" != line)
        {
            // Process this flow
            try
            {
                // 0:starttime, 1:dur, 2:proto, 3:saddr, 4:sport, 5:dir, 6:daddr: 7:dport, 8:state, 9:stos,  10:dtos, 11:pkts, 12:bytes
                column_values.clear();
                vectorize_input(line, column_values);
                if(!validate_netflow(column_values))
                {
                    cerr << "WARNING: Processor::start() - Invalid netflow received: " << line <<endl;
                    return false;
                }
                if (!slot_starttime.get_state())
                {
                    // First flow
                    slot_starttime = Datetime(get_time_data(column_values[0]));
                    slot_endtime = slot_starttime;
                    slot_endtime.update_time(slot_width * 60);
                }
                Datetime flowtime = Datetime(get_time_data(column_values[0]));
                if (flowtime.get_total_seconds() >= slot_starttime.get_total_seconds() && flowtime.get_total_seconds() < slot_endtime.get_total_seconds())
                {
                    // Inside the slot
                    std::string recv_tuple = column_values[3] + '-' + column_values[6] + '-' + column_values[7] + '-' + column_values[2];
                    std::shared_ptr<Tuple> *tuple = get_tuple(recv_tuple);
                    tuples_in_this_time_slot[(*tuple)->get_id()] = tuple;
                    (*tuple)->add_new_flow(column_values);
                    // Detection
                    detect(tuple);
                }
                else if (flowtime.get_total_seconds() > slot_endtime.get_total_seconds())
                {
                    // Out of time slot
                    process_out_of_time_slot(column_values);
                }
            }
            //This is for unhandled exception - ideally this catch block is not needed.
            catch(int e)
            {
                throw e;
            }
            catch(std::exception &e)
            {
                cerr << "WARNING: Probably empty file.\n" << e.what() <<endl;
                return false;
            }
            catch(...)
            {
                cerr << "WARNING: Probably empty file." <<endl;
                return false;
            }

        }
        else
        {
            try
            {
                //Process the last flows in the last time slot.
                process_out_of_time_slot(column_values);
            }
            catch(int e)
            {
                throw e;
            }
            //This is for unhandled exception - ideally this catch block is not needed.
            catch(std::exception &e)
            {
                cerr << "WARNING: Probably empty file.\n" << e.what() <<endl;
                return false;
            }
            catch(...)
            {
                cerr << "WARNING: Probably empty file." <<endl;
                //Here for some reasom we still miss the last flow. But since is just one I will let it go for now.
                return false;
            }
        }
    }
    catch(int e)
    {
        cerr << "ERROR: Problem with Processor::start()" <<endl;
        throw e;
    }
    catch(std::exception &e)
    {
        cerr << "ERROR: Problem with Processor::start().\n" << e.what() <<endl;
        throw(ERROR_UNEXPECTED_ERROR);
    }
    catch(...)
    {
        cerr << "ERROR: Problem with Processor::start()." <<endl;
        throw(ERROR_UNEXPECTED_ERROR);
    }
    // return true if flow successfully processed.
    return true;
}

void Processor::addToQueue(std::string line)
{
    que.push(line);
}
bool Processor::checkQueueEmpty()
{
    return que.empty();
}
std::string Processor::getNext()
{
    return que.front();
}
void Processor::removeNext()
{
    return que.pop();
}
}

