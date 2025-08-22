#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstdlib>
#include <regex>

struct Rule {
    enum class Action { ALLOW, BLOCK };
    Action action;
    std::string cidr; // source IPv4 or CIDR
};

static bool runCmd(const std::string &cmd) {
    int rc = std::system(cmd.c_str());
    if (rc != 0) {
        std::cerr << "Command failed (" << rc << "): " << cmd << std::endl;
        return false;
    }
    return true;
}

static bool checkOrAdd(const std::string &ruleSpec) {
    // Idempotently add an iptables rule: if not present (-C fails), then -A.
    // ruleSpec must include everything AFTER iptables, e.g. "-A INPUT ... -j ACCEPT"
    std::string checkCmd = "iptables -C " + ruleSpec;
    int rc = std::system(checkCmd.c_str());
    if (rc == 0) {
        // Already present
        return true;
    }
    // Not present, append it
    return runCmd("iptables -" + ruleSpec.substr(1)); // replace -C with -A by dropping first char
}

static bool ensureBasePolicy() {
    bool ok = true;
    // Default policies
    ok &= runCmd("iptables -P INPUT DROP");
    ok &= runCmd("iptables -P FORWARD DROP");
    ok &= runCmd("iptables -P OUTPUT ACCEPT");

    // Flush custom chains (we keep policies as set above)
    ok &= runCmd("iptables -F INPUT");
    ok &= runCmd("iptables -F FORWARD");
    ok &= runCmd("iptables -F OUTPUT");

    // Allow loopback
    ok &= checkOrAdd("-A INPUT -i lo -j ACCEPT");
    ok &= checkOrAdd("-A OUTPUT -o lo -j ACCEPT");

    // Allow established/related inbound
    ok &= checkOrAdd("-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");

    // (Optional) Allow ping (ICMP echo-request) — comment out if undesired
    ok &= checkOrAdd("-A INPUT -p icmp --icmp-type echo-request -j ACCEPT");

    return ok;
}

static bool applyRule(const Rule &r) {
    std::ostringstream oss;
    if (r.action == Rule::Action::ALLOW) {
        // Allow source CIDR to reach us inbound (INPUT)
        oss << "-A INPUT -s " << r.cidr << " -j ACCEPT";
        return checkOrAdd(oss.str());
    } else {
        // Explicitly drop source CIDR inbound
        oss << "-A INPUT -s " << r.cidr << " -j DROP";
        return checkOrAdd(oss.str());
    }
}

static bool parseRuleLine(const std::string &line, Rule &out) {
    std::string s = line;
    // Trim
    auto notSpace = [](int ch){ return !std::isspace(ch); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), notSpace));
    s.erase(std::find_if(s.rbegin(), s.rend(), notSpace).base(), s.end());
    if (s.empty() || s[0] == '#') return false; // skip blanks/comments

    std::istringstream iss(s);
    std::string action, cidr;
    if (!(iss >> action >> cidr)) return false;

    for (auto &c : action) c = std::toupper(c);
    if (action == "ALLOW") out.action = Rule::Action::ALLOW;
    else if (action == "BLOCK") out.action = Rule::Action::BLOCK;
    else return false;

    // Basic IPv4/CIDR sanity (not exhaustive)
    static const std::regex cidrRe(R"(^([0-9]{1,3}\.){3}[0-9]{1,3}(\/(\d|[12]\d|3[0-2]))?$)");
    if (!std::regex_match(cidr, cidrRe)) {
        std::cerr << "Invalid CIDR/IP: " << cidr << std::endl;
        return false;
    }
    out.cidr = cidr;
    return true;
}

static bool loadRulesFile(const std::string &path, std::vector<Rule> &rules) {
    std::ifstream in(path);
    if (!in) {
        std::cerr << "Could not open rules file: " << path << std::endl;
        return false;
    }
    std::string line;
    int lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        Rule r;
        if (parseRuleLine(line, r)) {
            rules.push_back(r);
        } else {
            // Ignore empty/comment/invalid lines but warn on non-comment garbage
            std::string s = line;
            s.erase(std::remove_if(s.begin(), s.end(), ::isspace), s.end());
            if (!s.empty() && s[0] != '#') {
                std::cerr << "Warning: skipped invalid rule at line " << lineno << std::endl;
            }
        }
    }
    return true;
}

static bool applyRules(const std::vector<Rule> &rules) {
    bool ok = true;
    for (const auto &r : rules) {
        ok &= applyRule(r);
    }
    return ok;
}

static bool listRules() {
    return runCmd("iptables -S");
}

static bool flushAll() {
    bool ok = true;
    ok &= runCmd("iptables -F"); // Flush all built-in chains
    ok &= runCmd("iptables -X"); // Delete any user-defined chains
    // Keep default policies as-is (user can set manually if needed)
    return ok;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: sudo " << argv[0] << " [--apply rules.txt | --rebuild rules.txt | --flush | --list]\n";
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == std::string("--apply")) {
        std::string path = (argc >= 3) ? argv[2] : "rules.txt";
        if (!ensureBasePolicy()) {
            std::cerr << "Failed to set base policy" << std::endl;
            return 2;
        }
        std::vector<Rule> rules;
        if (!loadRulesFile(path, rules)) return 3;
        if (!applyRules(rules)) return 4;
        std::cout << "Applied base policy and " << rules.size() << " rules from '" << path << "'" << std::endl;
        return 0;
    }

    if (cmd == std::string("--rebuild")) {
        std::string path = (argc >= 3) ? argv[2] : "rules.txt";
        if (!flushAll()) return 5;
        if (!ensureBasePolicy()) return 6;
        std::vector<Rule> rules;
        if (!loadRulesFile(path, rules)) return 7;
        if (!applyRules(rules)) return 8;
        std::cout << "Rebuilt firewall and applied " << rules.size() << " rules from '" << path << "'" << std::endl;
        return 0;
    }

    if (cmd == std::string("--flush")) {
        if (!flushAll()) return 9;
        std::cout << "Flushed all rules. NOTE: Default policies unchanged." << std::endl;
        return 0;
    }

    if (cmd == std::string("--list")) {
        if (!listRules()) return 10;
        return 0;
    }

    std::cerr << "Unknown command: " << cmd << std::endl;
    return 1;
}
