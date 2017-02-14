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
*    util.cc is written by Sachin Vernekar (savernek@cisco.com)
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
#include "util.h"
#include <iostream>
#include <ctime>
#include <stdlib.h>
#include <sstream>
#include <cmath>
#include <iterator>
#include <stdexcept>
#include <cstring>
#include "constants.h"

using std::cout;
using std::endl;
using std::cerr;

std::string trim(const std::string& str, const std::string& whitespace)
{
    const auto strBegin = str.find_first_not_of(whitespace);
    if (strBegin == std::string::npos)
        return ""; // no content

    const auto strEnd = str.find_last_not_of(whitespace);
    const auto strRange = strEnd - strBegin + 1;

    return str.substr(strBegin, strRange);
}

void split(const std::string &s, char delim, std::vector<std::string> &elems)
{
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim))
    {
        item = trim(item);
        elems.push_back(item);
    }
}

std::string join(std::vector<std::string> &vec) {
    std::ostringstream oss;
    std::copy(vec.begin(), vec.end(), std::ostream_iterator<std::string>(oss, ","));
    std::string result( oss.str() );
    return result;
}

//This function returns the time in array format
std::vector<int> get_time_data(const std::string &str) throw(int)
{
    std::vector<int> time_data;
    std::vector<std::string> date_time;
    std::vector<std::string> date;
    std::vector<std::string> time;
    std::vector<std::string> sec_ms;

    split(str, ' ', date_time);
    if(date_time.size() >= 2)
    {
        split(date_time.at(0), '/', date);
        split(date_time.at(1), ':', time);
        if(date.size() >= 3 && time.size() >= 3)
        {
            try
            {
                time_data.push_back(atoi(date.at(0).c_str()));
                time_data.push_back(atoi(date.at(1).c_str()));
                time_data.push_back(atoi(date.at(2).c_str()));

                time_data.push_back(atoi(time.at(0).c_str()));
                time_data.push_back(atoi(time.at(1).c_str()));

                split(time.at(2), '.', sec_ms);
                if(sec_ms.size() > 1) {
                    time_data.push_back(atoi(sec_ms.at(0).c_str()));
                    time_data.push_back(atoi(sec_ms.at(1).c_str()));
                }
            }
            catch (const std::invalid_argument& ia)
            {
                //do nothing - handled below
            }
        }
    }
    if(time_data.size() != 7)
    {
        cerr << "ERROR: Problem in util.cc:get_time_data() - Invalid time string: " << str <<endl;
        throw ERROR_INVALID_TIME;
    }
    return time_data;
}

Timedelta::Timedelta()
{
    total_seconds = 0.0;
    state = false;
}

Timedelta::Timedelta(bool state, double total_seconds)
{
    this->total_seconds = total_seconds;
    this->state = state;
}

double Timedelta::get_total_seconds()
{
    return total_seconds;
}

void Timedelta::set_total_seconds(double total_seconds)
{
    this->total_seconds = total_seconds;
}

bool Timedelta::get_state()
{
    return state;
}
void Timedelta::set_state(bool state)
{
    this->state = state;
}


Datetime::Datetime()
{
    state = false;
}

Datetime::Datetime(std::vector<int> time_info)
{
    memset(&tm, 0, sizeof(tm));
    tm.tm_sec = time_info.at(5);
    tm.tm_min = time_info.at(4);
    tm.tm_hour = time_info.at(3);
    tm.tm_mday = time_info.at(2);
    tm.tm_mon = time_info.at(1)-1;
    tm.tm_year = time_info.at(0)-1900;
    mktime(&tm);
    this->microseconds = time_info.at(6);
    state = true;
}

Datetime::Datetime(std::string time_str, int microseconds)
{
    memset(&tm, 0, sizeof(tm));
    strptime(time_str.c_str(), "%Y/%m/%d %H:%M:%S", &tm);
    mktime(&tm);
    this->microseconds = microseconds;
    state = true;
}

void Datetime::update_time(double seconds)
{
    tm.tm_sec += seconds;
    mktime(&tm);
    double intpart, fractpart;
    fractpart = modf (seconds , &intpart);
    microseconds += fractpart*1000000;
}

double Datetime::get_total_seconds()
{
    return mktime(&tm) + (microseconds*1.0/1000000);
}

std::string Datetime::get_time_string()
{
    char buf[32];
    std::strftime(buf, 32, "%Y-%m-%d %H:%M:%S", &tm);
    std::string ms =  std::to_string(microseconds);
    return std::string(buf) + "." + std::string(6 - ms.length(), '0') + ms;
}

Timedelta Datetime::operator-(Datetime& dt)
{
    Timedelta td = Timedelta(true,difftime(mktime(&(this->tm)), mktime(&(dt.tm))) + (this->microseconds-dt.microseconds)*1.0/1000000);
    return td;
}

bool Datetime::get_state()
{
    return state;
}

void Datetime::set_state(bool state)
{
    this->state = state;
}

Tuple::Tuple(std::string tuple4)
{
    id = tuple4;
    amount_of_flows = 0;
    std::vector<std::string> x;
    split(tuple4, '-',x);
    src_ip = x[0];
    dst_ip = x[1];
    dst_port = x[2];
    protocol = x[3];
    state_so_far = "";
    winner_model_id = false;
    winner_model_distance = INFINITY;
    proto = "";
    current_size = -1;
    current_duration = -1;
    previous_size = -1;
    previous_duration = -1;
    // Thresholds
    tto = Timedelta(true,3600.0);
    tt1 = 1.05;
    tt2 = 1.3;
    tt3 = 5;
    td1 = 0.1;
    td2 = 10;
    ts1 = 250;
    ts2 = 1100;
    // The state
    state ="";
    // Final values for getting the state
    duration = -1;
    size = -1;
    periodic = -1;
    // By default print all tuples. Depends on the arg
    should_be_printed = true;
    //[TO-DO: savernek] As of now there is no desc as we don't have ip address info library
    desc = "";
    // After a tuple is detected, min_state_len holds the lower letter position in the state
    // where the detection happened.
    min_state_len = 0;
    // After a tuple is detected, max_state_len holds the max letter position in the state
    // where the detection happened. The new arriving letters to be detected are between max_state_len and the real end of the state
    max_state_len = 0;
    detected_label = "";
    // verbosity
    verbose = 0;
}

void Tuple::set_detected_label(std::string label)
{
    detected_label = label;
}

void Tuple::unset_detected_label()
{
    detected_label = "";
}

std::string Tuple::get_detected_label()
{
    return detected_label;
}

std::string Tuple::get_state_detected_last()
{
    if(max_state_len == 0)
    {
        // First time before any detection
        return state.substr(min_state_len);
    }
    // After the first detection
    return state.substr(min_state_len, max_state_len-min_state_len);
}

void Tuple::set_min_state_len(int state_len)
{
    min_state_len = state_len;
}

int Tuple::get_min_state_len()
{
    return min_state_len;
}

void Tuple::set_max_state_len(int state_len)
{
    max_state_len = state_len;
}

int Tuple::get_max_state_len()
{
    return max_state_len;
}

std::string Tuple::get_protocol()
{
    return protocol;
}

std::string Tuple::get_state()
{
    return state;
}

void Tuple::set_verbose(int verbose)
{
    this->verbose = verbose;
}

void Tuple::add_new_flow(std::vector<std::string> column_values)
{
    // Add new stuff about the flow in this tuple
    // 0:starttime, 1:dur, 2:proto, 3:saddr, 4:sport, 5:dir, 6:daddr: 7:dport, 8:state, 9:stos,  10:dtos, 11:pkts, 12:bytes
    // Store previous
    previous_size = current_size;
    previous_duration = current_duration;
    previous_time = datetime;
    if(verbose > 2)
    {
        cout << "\nAdding flow " << join(column_values) <<endl;
    }
    // Get the startime
    datetime = Datetime(get_time_data(column_values[0]));
    // Get the size
    try
    {
        if(column_values.size() > 12)
        {
            current_size = atof(column_values.at(12).c_str());
            if(current_size < 0)
                current_size = 0.0;
        }
        else
        {
            current_size = 0.0;
        }
    }
    catch (const std::invalid_argument& ia)
    {
        // It can happen that we dont have this value in the binetflow
        current_size = 0.0;
    }
    try
    {
        current_duration = atof(column_values[1].c_str());
        if(current_duration < 0)
            current_duration = 0.0;
    }
    catch (const std::invalid_argument& ia)
    {
        // It can happen that we dont have this value in the binetflow
        current_duration = 0.0;
    }
    // Get the proto
    proto = column_values[2];
    // Get the amount of flows
    amount_of_flows += 1;
    // Update value of T1
    T1 = T2;
    if(previous_time.get_state())
    {
        //Update value of T2
        T2 = datetime - previous_time;
        // Are flows sorted?
        if(T2.get_total_seconds() < 0)
        {
            // Flows are not sorted
            if (verbose > 2)
                cout << "@" <<endl;
            // What is going on here when the flows are not ordered?? Are we losing flows?
        }
    }
    else
    {
        T2.set_state(false);
    }
    // Compute the rest
    this->compute_periodicity();
    this->compute_duration();
    this->compute_size();
    this->compute_state();
    this->compute_symbols();
    this->do_print();
    if (verbose > 1)
        cout << "\tTuple "<< this->get_id() <<" Amount of flows so far: " << amount_of_flows<<endl;
    //for functional test
    if(!verbose)
        cout << this->get_id() + ": " + this->get_state() << endl;
}

void Tuple::compute_periodicity()
{
    // If either T1 or T2 are False
    if ((T1.get_state() == false) || (T2.get_state() == false))
    {
        periodic = -1;
    }
    else if(T2.get_total_seconds() >= tto.get_total_seconds())
    {
        int t2_in_hours = T2.get_total_seconds() / tto.get_total_seconds();
        // Should be int always
        for(int i=0; i<t2_in_hours; i++)
            state += '0';
    }
    else if(T1.get_total_seconds() >= tto.get_total_seconds())
    {
        int t1_in_hours = T1.get_total_seconds() / tto.get_total_seconds();
        // Should be int always
        for(int i=0; i<t1_in_hours; i++)
            state += '0';
    }
    if(T1.get_state() == true && T2.get_state() == true)
    {
        if(T2.get_total_seconds() >= T1.get_total_seconds())
        {
            if(T1.get_total_seconds() > 0)
            {
                TD.set_state(true);
                TD.set_total_seconds(T2.get_total_seconds() / T1.get_total_seconds());
            }
            else
            {
                //Division by zero
                TD.set_state(true);
                TD.set_total_seconds(1);
            }
        }
        else
        {
            if(T2.get_total_seconds() > 0)
            {
                TD.set_state(true);
                TD.set_total_seconds(T1.get_total_seconds() / T2.get_total_seconds());
            }
            else
            {
                //Division by zero
                TD.set_state(true);
                TD.set_total_seconds(1);
            }
        }
        // Decide the periodic based on TD and the thresholds
        if(TD.get_total_seconds() <= tt1)
            periodic = 1;// Strongly periodic
        else if (TD.get_total_seconds() < tt2)
            periodic = 2;// Weakly periodic
        else if (TD.get_total_seconds() < tt3)
            periodic = 3;// Weakly not periodic
        else
            periodic = 4;
        if (verbose > 2)
            cout << "\tPeriodicity: " << periodic <<endl;
    }
}

void Tuple::compute_duration()
{
    if (current_duration <= td1)
        duration = 1;
    else if (current_duration > td1 && current_duration <= td2)
        duration = 2;
    else if (current_duration > td2)
        duration = 3;
    if (verbose > 2)
        cout << "\tDuration: " << duration <<endl;
}

void Tuple::compute_size()
{
    if (current_size <= ts1)
        size = 1;
    else if (current_size > ts1 && current_size <= ts2)
        size = 2;
    else if (current_size > ts2)
        size = 3;
    if (verbose > 2)
        cout << "\tSize: "<< size <<endl;
}

void Tuple::compute_state()
{
    char state_array[5][3][3] = {	{{'1', '2', '3',}, {'4', '5', '6',}, {'7', '8', '9',},}, // Periodicity = -1
        {{'a', 'b', 'c',}, {'d', 'e', 'f',}, {'g', 'h', 'i',},}, // Periodicity = 0
        {{'A', 'B', 'C',}, {'D', 'E', 'F',}, {'G', 'H', 'I',},}, // Periodicity = 1
        {{'r', 's', 't',}, {'u', 'v', 'w',}, {'x', 'y', 'z',},}, // Periodicity = 2
        {{'R', 'S', 'T',}, {'U', 'V', 'W',}, {'X', 'Y', 'Z',},}, // Periodicity = 3
    };
    int search_periodic = (periodic < 0) ? (periodic + 1) : periodic;
    int search_size = size - 1;
    int search_duration = duration - 1;

    state += state_array[search_periodic][search_size][search_duration];
}

void Tuple::compute_symbols()
{
    if (T2.get_state())
    {
        if (T2.get_total_seconds() <= 5.0)
        {
            state += '.';
        }
        else if (T2.get_total_seconds() <= 60)
        {
            state += ',';
        }
        else if (T2.get_total_seconds() <= 300)
        {
            state += '+';
        }
        else if (T2.get_total_seconds() <= 3600)
        {
            state += '*';
        }
        if (verbose > 2)
            cout << "\tTD: " <<TD.get_total_seconds() << " T2: "<<T2.get_total_seconds() <<" T1: "<<T1.get_total_seconds() <<" State: "<<state;
    }
}

std::string Tuple::get_id()
{
    return id;
}

std::string Tuple::print_tuple_detected() {
    return get_id() + " []" + " (" + std::to_string(amount_of_flows) + "): " + get_state_detected_last() + "  Detected as: "  + get_detected_label();
}

void Tuple::dont_print() {
    if(verbose > 3) {
        cout << "\tDont print tuple " << get_id() <<endl;
    }
    should_be_printed = false;
}

void Tuple::do_print() {
    should_be_printed = true;
    if(verbose > 3) {
        cout << "\tPrint tuple " << get_id() <<endl;
    }
}

void vectorize_input(const std::string &ip, std::vector<std::string> &vec)
{
    split(ip, ',', vec);
}

bool validate_netflow(std::vector<std::string> netflow)
{
    bool is_valid = false;
    if(netflow.size() >= 12 && !trim(netflow[2]).empty() && !trim(netflow[3]).empty() && !trim(netflow[6]).empty())
    {
        try
        {
            get_time_data(netflow[0]);
            is_valid = true;
        }
        catch (int e)
        {
            // do nothing
        }
    }
    return is_valid;
}

DetectionInfo::DetectionInfo()
{
    matched = false;
    label = "";
    best_model_matching_len = -1;
}

DetectionInfo::DetectionInfo(bool matched, std::string label, int best_model_matching_len)
{
    this->matched = matched;
    this->label = label;
    this->best_model_matching_len = best_model_matching_len;
}
