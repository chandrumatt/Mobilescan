"use client";
import { useState, useEffect } from "react";
import {
  Shield,
  Upload,
  FileText,
  Mail,
  Globe,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Zap,
  Activity,
  Search,
  History,
  Download,
  Trash2,
  Eye,
  Calendar,
} from "lucide-react";
import Link from "next/link";

const YARA_RULE_SETS = [
  {
    name: "Malware Signatures",
    description: "Scanning for known malware patterns",
    color: "text-red-400",
  },
  {
    name: "Suspicious Network Activity",
    description: "Analyzing network communications",
    color: "text-orange-400",
  },
  {
    name: "Phishing & Social Engineering",
    description: "Detecting phishing attempts",
    color: "text-yellow-400",
  },
  {
    name: "Cryptocurrency Miners",
    description: "Checking for hidden mining code",
    color: "text-purple-400",
  },
  {
    name: "System File Integrity",
    description: "Verifying system file authenticity",
    color: "text-blue-400",
  },
];

const uploadScan = async (file, onProgress) => {
  onProgress({ currentRule: 0, progress: 10, scanning: true });

  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch("http://localhost:4000/scan", {
    method: "POST",
    body: formData,
  });

  const data = await response.json();
  onProgress({ currentRule: -1, progress: 100, scanning: false });
  return [data];
};

export default function Scanner() {
  const [file, setFile] = useState(null);
  const [fileType, setFileType] = useState("all");
  const [result, setResult] = useState([]);
  const [history, setHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [selectedHistoryItem, setSelectedHistoryItem] = useState(null);
  const [scanProgress, setScanProgress] = useState({
    currentRule: -1,
    progress: 0,
    scanning: false,
  });

  // Load history from localStorage on component mount
  useEffect(() => {
    const savedHistory = localStorage.getItem("scanHistory");
    if (savedHistory) {
      try {
        const parsedHistory = JSON.parse(savedHistory);
        setHistory(Array.isArray(parsedHistory) ? parsedHistory : []);
      } catch (e) {
        console.error("Failed to parse history from localStorage", e);
        setHistory([]);
      }
    } else {
      // For demo purposes, we'll use some sample data if no history exists
      const sampleHistory = [
        {
          id: "1",
          filename: "document.pdf",
          riskLevel: "low",
          uploadedAt: new Date(Date.now() - 86400000).toISOString(),
          yaraMatches: "[]",
          regexMatches: '{"emails":[],"ips":[],"patterns":[]}',
          scanStats: {
            totalRules: 150,
            matchedRules: 0,
            scanDuration: "00:01:23",
          },
        },
        {
          id: "2",
          filename: "suspicious.exe",
          riskLevel: "high",
          uploadedAt: new Date(Date.now() - 172800000).toISOString(),
          yaraMatches: '["Trojan.Win32.Generic", "Malware.Suspicious"]',
          regexMatches:
            '{"emails":["malware@bad.com"],"ips":["192.168.1.100"],"patterns":["crypto_miner"]}',
          scanStats: {
            totalRules: 150,
            matchedRules: 3,
            scanDuration: "00:02:45",
          },
        },
      ];
      setHistory(sampleHistory.slice(0, 2)); // Only add 2 sample items
    }
  }, []);

  // Save to localStorage whenever history changes (limit to 10 items)
  useEffect(() => {
    if (history.length > 0) {
      const limitedHistory = history.slice(0, 10); // Keep only the 10 most recent items
      localStorage.setItem("scanHistory", JSON.stringify(limitedHistory));
    } else {
      localStorage.removeItem("scanHistory");
    }
  }, [history]);

  const handleUpload = async () => {
    if (!file) return;
    try {
      const res = await uploadScan(file, setScanProgress);
      const scanResults = Array.isArray(res) ? res : [res];

      setResult(scanResults);

      // Add to history with unique ID and timestamp
      const historyEntry = scanResults.map((item) => ({
        ...item,
        id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
        uploadedAt: new Date().toISOString(),
      }));

      // Add new items to the beginning and limit to 10
      setHistory((prev) => [...historyEntry, ...prev].slice(0, 10));
    } catch (error) {
      console.error("Scan failed:", error);
      alert("Scan failed. Please try again.");
    }
  };

  const safeParse = (val, fallback) => {
    if (!val) return fallback;
    try {
      const parsed = JSON.parse(val);
      return typeof parsed === "object" ? parsed : fallback;
    } catch {
      return fallback;
    }
  };

  const parsedResults = result.map((item) => ({
    ...item,
    yaraMatches: safeParse(item.yaraMatches, []),
    regexMatches: safeParse(item.regexMatches, {
      emails: [],
      ips: [],
      patterns: [],
    }),
    scanStats: item.scanStats || {
      totalRules: 0,
      matchedRules: 0,
      scanDuration: "00:00:00",
    },
  }));

  const parsedHistory = history.map((item) => ({
    ...item,
    yaraMatches: safeParse(item.yaraMatches, []),
    regexMatches: safeParse(item.regexMatches, {
      emails: [],
      ips: [],
      patterns: [],
    }),
    scanStats: item.scanStats || {
      totalRules: 0,
      matchedRules: 0,
      scanDuration: "00:00:00",
    },
  }));

  const getRiskColor = (riskLevel) => {
    switch (riskLevel?.toLowerCase()) {
      case "high":
        return "border-red-500 bg-red-900/20";
      case "medium":
        return "border-yellow-500 bg-yellow-900/20";
      case "low":
        return "border-green-500 bg-green-900/20";
      default:
        return "border-gray-600 bg-gray-800/50";
    }
  };

  const getRiskIcon = (riskLevel) => {
    switch (riskLevel?.toLowerCase()) {
      case "high":
        return <XCircle className="w-5 h-5 text-red-400" />;
      case "medium":
        return <AlertTriangle className="w-5 h-5 text-yellow-400" />;
      case "low":
        return <CheckCircle className="w-5 h-5 text-green-400" />;
      default:
        return <Shield className="w-5 h-5 text-gray-400" />;
    }
  };

  const getTotalMatches = (item) => {
    const yaraMatches = safeParse(item.yaraMatches, []);
    const regexMatches = safeParse(item.regexMatches, {});
    return (
      (regexMatches.emails?.length || 0) +
      (regexMatches.ips?.length || 0) +
      (regexMatches.patterns?.length || 0) +
      (yaraMatches?.length || 0)
    );
  };

  const downloadReport = (item) => {
    const report = {
      filename: item.filename,
      scanDate: new Date(item.uploadedAt).toLocaleString(),
      riskLevel: item.riskLevel,
      scanStats: item.scanStats,
      yaraMatches: safeParse(item.yaraMatches, []),
      regexMatches: safeParse(item.regexMatches, {}),
      totalMatches: getTotalMatches(item),
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `scan-report-${item.filename}-${
      new Date().toISOString().split("T")[0]
    }.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const downloadAllHistory = () => {
    const allReports = parsedHistory.map((item) => ({
      filename: item.filename,
      scanDate: new Date(item.uploadedAt).toLocaleString(),
      riskLevel: item.riskLevel,
      scanStats: item.scanStats,
      yaraMatches: safeParse(item.yaraMatches, []),
      regexMatches: safeParse(item.regexMatches, {}),
      totalMatches: getTotalMatches(item),
    }));

    const blob = new Blob([JSON.stringify(allReports, null, 2)], {
      type: "application/json",
    });

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `all-scan-history-${
      new Date().toISOString().split("T")[0]
    }.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const clearHistory = () => {
    if (confirm("Are you sure you want to clear all scan history?")) {
      setHistory([]);
      setShowHistory(false);
      localStorage.removeItem("scanHistory");
    }
  };

  const viewHistoryItem = (item) => {
    setSelectedHistoryItem(item);
    setResult([item]);
    setShowHistory(false);
  };

  const acceptedTypes = {
    all: "*",
    pdf: ".pdf",
    db: ".db,.sqlite",
    zip: ".zip,.tar,.gz,.tgz",
    txt: ".txt",
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Shield className="w-12 h-12 text-cyan-400 mr-3" />
            <h1 className="text-4xl font-bold">Forensics Mobile</h1>
          </div>
          <p className="text-gray-400">Advanced Malware Detection System</p>
        </div>

        {/* File Selection */}
        <div className="bg-gray-800 rounded-lg p-6 mb-6">
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Select File for Analysis
            </label>
            <div className="flex items-center space-x-4 flex-wrap gap-2">
              <select
                value={fileType}
                onChange={(e) => setFileType(e.target.value)}
                className="px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-300"
              >
                <option value="all">All Files</option>
                <option value="pdf">PDF</option>
                <option value="db">SQLite / DB</option>
                <option value="zip">Archive Files</option>
                <option value="txt">Text Files</option>
              </select>

              <input
                type="file"
                accept={acceptedTypes[fileType]}
                onChange={(e) => setFile(e.target.files?.[0] || null)}
                className="flex-1 min-w-0 px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-300 file:bg-cyan-600 file:text-white"
              />

              <button
                onClick={handleUpload}
                disabled={!file || scanProgress.scanning}
                className="bg-cyan-600 hover:bg-cyan-700 px-6 py-2 rounded disabled:opacity-50 whitespace-nowrap"
              >
                {scanProgress.scanning ? (
                  <span className="flex items-center">
                    <Activity className="w-4 h-4 mr-2 animate-pulse" />
                    Scanning...
                  </span>
                ) : (
                  <span className="flex items-center">
                    <Upload className="w-4 h-4 mr-2" />
                    Start Scan
                  </span>
                )}
              </button>

              <button
                onClick={() => setShowHistory(!showHistory)}
                className="bg-blue-600 hover:bg-blue-700 px-6 py-2 rounded flex items-center  whitespace-nowrap"
              >
                <History className="w-4 h-4 mr-2" />
                History ({history.length})
              </button>

              <Link href="/whatsappupload" className="mb-[13px]">
                <button className="mt-4 bg-green-600 hover:bg-green-700 px-6 py-2 rounded text-white">
                  Upload WhatsApp File
                </button>
              </Link>
            </div>
          </div>
        </div>

        {/* History Panel */}
        {showHistory && (
          <div className="bg-gray-800 rounded-lg p-6 mb-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-semibold flex items-center">
                <History className="w-6 h-6 mr-3 text-blue-400" />
                Scan History
              </h3>
              <div className="flex space-x-2">
                <button
                  onClick={downloadAllHistory}
                  className="bg-green-600 hover:bg-green-700 px-4 py-2 rounded flex items-center text-sm"
                  disabled={history.length === 0}
                >
                  <Download className="w-4 h-4 mr-2" />
                  Download All
                </button>
                <button
                  onClick={clearHistory}
                  className="bg-red-600 hover:bg-red-700 px-4 py-2 rounded flex items-center text-sm"
                  disabled={history.length === 0}
                >
                  <Trash2 className="w-4 h-4 mr-2" />
                  Clear History
                </button>
              </div>
            </div>

            {history.length === 0 ? (
              <div className="text-center py-8">
                <History className="w-12 h-12 text-gray-600 mx-auto mb-4" />
                <p className="text-gray-400">No scan history available</p>
              </div>
            ) : (
              <div className="space-y-3 max-h-96 overflow-y-auto pr-2">
                {parsedHistory.map((item) => (
                  <div
                    key={item.id}
                    className={`p-4 rounded-lg border-l-4 ${getRiskColor(
                      item.riskLevel
                    )}`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <FileText className="w-6 h-6 text-gray-400" />
                        <div>
                          <h4 className="font-semibold">{item.filename}</h4>
                          <div className="flex items-center space-x-4 text-sm text-gray-400">
                            <span className="flex items-center">
                              <Calendar className="w-3 h-3 mr-1" />
                              {new Date(item.uploadedAt).toLocaleDateString()}
                            </span>
                            <span>{getTotalMatches(item)} matches</span>
                            <span className="flex items-center">
                              {getRiskIcon(item.riskLevel)}
                              <span className="ml-1 capitalize">
                                {item.riskLevel} Risk
                              </span>
                            </span>
                          </div>
                        </div>
                      </div>
                      <div className="flex space-x-2">
                        <button
                          onClick={() => viewHistoryItem(item)}
                          className="bg-blue-600 hover:bg-blue-700 px-3 py-1 rounded text-sm flex items-center"
                        >
                          <Eye className="w-3 h-3 mr-1" />
                          View
                        </button>
                        <button
                          onClick={() => downloadReport(item)}
                          className="bg-green-600 hover:bg-green-700 px-3 py-1 rounded text-sm flex items-center"
                        >
                          <Download className="w-3 h-3 mr-1" />
                          Download
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {scanProgress.scanning && (
          <div className="bg-gray-800 rounded-lg p-6 mb-6">
            <div className="flex items-center mb-4">
              <Activity className="w-6 h-6 text-cyan-400 mr-3 animate-pulse" />
              <h3 className="text-xl font-semibold">
                YARA Rule Scanning in Progress
              </h3>
            </div>
            <div className="mb-6">
              <div className="flex justify-between text-sm text-gray-400 mb-2">
                <span>Overall Progress</span>
                <span>{scanProgress.progress}%</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-3">
                <div
                  className="bg-cyan-500 h-3 rounded-full transition-all duration-300"
                  style={{ width: `${scanProgress.progress}%` }}
                ></div>
              </div>
            </div>

            <div className="space-y-3">
              {YARA_RULE_SETS.map((ruleSet, index) => (
                <div key={index} className="flex items-center space-x-4">
                  <div className="w-6 h-6 flex items-center justify-center">
                    {index < scanProgress.currentRule ? (
                      <CheckCircle className="w-5 h-5 text-green-400" />
                    ) : index === scanProgress.currentRule ? (
                      <div className="w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin"></div>
                    ) : (
                      <div className="w-4 h-4 border-2 border-gray-600 rounded-full"></div>
                    )}
                  </div>
                  <div className="flex-1">
                    <div
                      className={`font-medium ${
                        index <= scanProgress.currentRule
                          ? ruleSet.color
                          : "text-gray-500"
                      }`}
                    >
                      {ruleSet.name}
                    </div>
                    <div className="text-sm text-gray-500">
                      {ruleSet.description}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {parsedResults.length > 0 && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h2 className="text-2xl font-bold flex items-center">
                <Search className="w-6 h-6 mr-3 text-cyan-400" />
                Scan Results
              </h2>
              <div className="flex space-x-2">
                <button
                  onClick={() => setResult([])}
                  className="bg-gray-600 hover:bg-gray-700 px-4 py-2 rounded flex items-center"
                >
                  Close Results
                </button>
                <button
                  onClick={() => downloadReport(parsedResults[0])}
                  className="bg-green-600 hover:bg-green-700 px-4 py-2 rounded flex items-center"
                >
                  <Download className="w-4 h-4 mr-2" />
                  Download Report
                </button>
              </div>
            </div>

            {parsedResults.map((item) => (
              <div
                key={item.id}
                className={`bg-gray-800 rounded-lg border-l-4 overflow-hidden ${getRiskColor(
                  item.riskLevel
                )}`}
              >
                <div className="p-6">
                  <div className="flex items-center justify-between mb-6">
                    <div className="flex items-center space-x-3">
                      <FileText className="w-8 h-8 text-gray-400" />
                      <div>
                        <h3 className="text-xl font-bold">{item.filename}</h3>
                        <p className="text-sm text-gray-400">
                          Scanned: {new Date(item.uploadedAt).toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <div
                      className={`flex items-center space-x-2 px-4 py-2 rounded-full border ${getRiskColor(
                        item.riskLevel
                      )}`}
                    >
                      {getRiskIcon(item.riskLevel)}
                      <span className="font-bold uppercase text-sm">
                        {item.riskLevel} Risk
                      </span>
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-4 mb-6 text-center">
                    <div className="bg-gray-700 rounded p-3">
                      <div className="text-2xl font-bold text-cyan-400">
                        {item.scanStats.totalRules}
                      </div>
                      <div className="text-sm text-gray-400">Rules Scanned</div>
                    </div>
                    <div className="bg-gray-700 rounded p-3">
                      <div className="text-2xl font-bold text-yellow-400">
                        {getTotalMatches(item)}
                      </div>
                      <div className="text-sm text-gray-400">Matches Found</div>
                    </div>
                    <div className="bg-gray-700 rounded p-3">
                      <div className="text-2xl font-bold text-green-400">
                        {item.scanStats.scanDuration}
                      </div>
                      <div className="text-sm text-gray-400">Scan Time</div>
                    </div>
                  </div>

                  <div className="grid md:grid-cols-2 gap-6">
                    {item.yaraMatches.length > 0 && (
                      <div className="bg-red-800 rounded p-4 mb-4 border border-red-500/30">
                        <h4 className="font-bold text-red-300 mb-3 flex items-center">
                          <Zap className="w-5 h-5 mr-2" />
                          YARA Matches ({item.yaraMatches.length})
                        </h4>
                        <div className="space-y-2">
                          {item.yaraMatches.map((ruleName, idx) => (
                            <div
                              key={`yara-${idx}`}
                              className="bg-red-900/40 border border-red-600/30 px-3 py-2 rounded text-sm text-red-200"
                            >
                              {ruleName}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {item.regexMatches.emails?.length > 0 && (
                      <div className="bg-gray-700 rounded p-4">
                        <h4 className="font-bold text-red-400 mb-3 flex items-center">
                          <Mail className="w-5 h-5 mr-2" />
                          Suspicious Emails ({item.regexMatches.emails.length})
                        </h4>
                        {item.regexMatches.emails.map((email, idx) => (
                          <div
                            key={`email-${idx}`}
                            className="bg-red-900/20 border border-red-500/30 px-3 py-2 rounded text-sm text-red-300"
                          >
                            {email}
                          </div>
                        ))}
                      </div>
                    )}

                    {item.regexMatches.ips?.length > 0 && (
                      <div className="bg-gray-700 rounded p-4">
                        <h4 className="font-bold text-orange-400 mb-3 flex items-center">
                          <Globe className="w-5 h-5 mr-2" />
                          Suspicious IPs ({item.regexMatches.ips.length})
                        </h4>
                        {item.regexMatches.ips.map((ip, idx) => (
                          <div
                            key={`ip-${idx}`}
                            className="bg-orange-900/20 border border-orange-500/30 px-3 py-2 rounded text-sm text-orange-300"
                          >
                            {ip}
                          </div>
                        ))}
                      </div>
                    )}

                    {item.regexMatches.patterns?.length > 0 && (
                      <div className="bg-yellow-700 rounded p-4 mb-4">
                        <h4 className="font-bold text-yellow-400 mb-3 flex items-center">
                          <AlertTriangle className="w-5 h-5 mr-2" />
                          Malware Patterns Detected
                        </h4>
                        <div className="flex flex-wrap gap-2">
                          {item.regexMatches.patterns.map((pattern, idx) => (
                            <span
                              key={`pattern-${idx}`}
                              className="bg-yellow-900/30 border border-yellow-500/50 text-yellow-300 px-3 py-1 rounded-full text-sm"
                            >
                              {pattern}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {!scanProgress.scanning && parsedResults.length === 0 && (
          <div className="text-center py-12">
            <Shield className="w-16 h-16 text-gray-600 mx-auto mb-4" />
            <p className="text-gray-400 text-lg">
              {history.length > 0
                ? "Select a file to scan or view your scan history"
                : "Upload a file to begin analysis"}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
