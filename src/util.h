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
*    util.h is written by Sachin Vernekar (savernek@cisco.com)
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
#ifndef UTIL_H
#define UTIL_H

#include <vector>
#include <string>

std::string trim(const std::string& str, const std::string& whitespace = " \t\n");

void split(const std::string &s, char delim, std::vector<std::string> &elems);

std::string join(std::vector<std::string> &vec);

std::vector<int> get_time_data(const std::string &str) throw(int);

void vectorize_input(const std::string &ip, std::vector<std::string> &vec);

bool validate_netflow(std::vector<std::string> netflow);

class Timedelta
{
public:
    double total_seconds;
    bool state;
    Timedelta();
    Timedelta(bool state, double total_seconds);
    double get_total_seconds();
    void set_total_seconds(double total_seconds);
    bool get_state();
    void set_state(bool state);
};

class Datetime
{
public:
    int microseconds;
    struct tm tm;
    bool state;
    Datetime();
    Datetime(std::vector<int> time_info);
    Datetime(std::string time_str, int microseconds);
    void update_time(double seconds);
    Timedelta operator-(Datetime& dt);
    bool get_state();
    void set_state(bool state);
    double get_total_seconds();
    std::string get_time_string();
};


class Tuple
{
    //The class to simply handle tuples
public:
    std::string id;
    int amount_of_flows;
    std::string src_ip;
    std::string dst_ip;
    std::string dst_port;
    std::string protocol;
    std::string state_so_far;
    bool winner_model_id;
    float winner_model_distance;
    std::string proto;
    Datetime datetime;
    Timedelta T1, T2, TD;
    float current_size;
    double current_duration;
    int previous_size;
    double previous_duration;
    Datetime previous_time;
    // Thresholds
    // Need to revisit this
    // In python it is self.tto = timedelta(seconds=3600)
    Timedelta tto;
    double tt1;
    double tt2;
    double tt3;
    double td1;
    double td2;
    float ts1;
    float ts2;
    // The state
    std::string state;
    // Final values for getting the state
    int duration;
    int size;
    int periodic;
    std::string  color;
    // By default print all tuples. Depends on the arg
    bool should_be_printed;
    std::string desc;
    // After a tuple is detected, min_state_len holds the lower letter position in the state
    // where the detection happened.
    int min_state_len;
    // After a tuple is detected, max_state_len holds the max letter position in the state
    // where the detection happened. The new arriving letters to be detected are between max_state_len and the real end of the state
    int max_state_len;
    std::string detected_label;
    // verbosity
    int verbose;
    Tuple(std::string tuple4);
    void set_detected_label(std::string label);
    void unset_detected_label();
    std::string get_detected_label();
    std::string get_state_detected_last();
    void set_min_state_len(int state_len);
    int get_min_state_len();
    void set_max_state_len(int state_len);
    int get_max_state_len();
    std::string get_protocol();
    std::string get_state();
    void set_verbose(int verbose);
    void add_new_flow(std::vector<std::string> column_values);
    void compute_periodicity();
    void compute_duration();
    void compute_size();
    void compute_state();
    void compute_symbols();
    std::string get_id();
    std::string print_tuple_detected();
    void dont_print();
    void do_print();
};

class DetectionInfo
{
public:
    bool matched;
    std::string label;
    int best_model_matching_len;
    DetectionInfo();
    DetectionInfo(bool matched, std::string label, int best_model_matching_len);
};
#endif
