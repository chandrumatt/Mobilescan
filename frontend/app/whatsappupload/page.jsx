'use client';
import { useState } from 'react';
import { Upload, FileText, CheckCircle, AlertCircle, X } from 'lucide-react';

export default function WhatsAppUpload() {
  const [file, setFile] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadSuccess, setUploadSuccess] = useState(false);
  const [result, setResult] = useState(null); // ✅ To store analysis result

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const droppedFile = e.dataTransfer.files[0];
      const validTypes = ['.zip', '.txt', '.json'];
      const fileExtension = '.' + droppedFile.name.split('.').pop().toLowerCase();

      if (validTypes.includes(fileExtension)) {
        setFile(droppedFile);
        setUploadSuccess(false);
        setResult(null);
      }
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setUploadSuccess(false);
      setResult(null);
    }
  };

  const handleUpload = async () => {
    if (!file) return;

    setUploading(true);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('http://localhost:8000/analyze-chat', {
        method: 'POST',
        body: formData,
      });

      const data = await response.json();
      console.log("Analysis Result:", data);

      setUploading(false);
      setUploadSuccess(true);
      setResult(data); // ✅ Store backend response for display

    } catch (error) {
      console.error("Upload error:", error);
      setUploading(false);
      alert("❌ Upload failed");
    }
  };

  const removeFile = () => {
    setFile(null);
    setUploadSuccess(false);
    setResult(null);
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-green-900 text-white p-6 flex items-center justify-center">
      <div className="bg-gray-800/80 backdrop-blur-lg p-8 rounded-2xl shadow-2xl w-full max-w-2xl border border-gray-700/50">
        {/* Header */}
        <div className="flex items-center mb-8 text-center justify-center">
          <div className="bg-green-500/20 p-4 rounded-full mr-4">
            <FileText className="w-8 h-8 text-green-400" />
          </div>
          <div>
            <h2 className="text-3xl font-bold bg-gradient-to-r from-white to-green-400 bg-clip-text text-transparent">
              Upload WhatsApp Chat
            </h2>
            <p className="text-gray-400 mt-1">Import your WhatsApp export files</p>
          </div>
        </div>

        {/* Upload Area */}
        <div
          className={`relative border-2 border-dashed rounded-xl p-8 transition-all duration-300 ${
            dragActive
              ? 'border-green-400 bg-green-400/10 scale-105'
              : file
              ? 'border-green-500 bg-green-500/5'
              : 'border-gray-600 hover:border-gray-500 hover:bg-gray-700/30'
          }`}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
        >
          {!file ? (
            <div className="text-center">
              <div className="mb-4">
                <Upload className={`w-16 h-16 mx-auto transition-all duration-300 ${
                  dragActive ? 'text-green-400 scale-110' : 'text-gray-400'
                }`} />
              </div>
              <h3 className="text-xl font-semibold mb-2">
                {dragActive ? 'Drop your file here' : 'Drag & drop your WhatsApp file'}
              </h3>
              <p className="text-gray-400 mb-4">
                or click to browse your files
              </p>
              <input
                type="file"
                accept=".zip,.txt,.json"
                onChange={handleFileChange}
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
              />
              <div className="flex flex-wrap justify-center gap-2 text-sm text-gray-500">
                <span className="bg-gray-700 px-3 py-1 rounded-full">.zip</span>
                <span className="bg-gray-700 px-3 py-1 rounded-full">.txt</span>
                <span className="bg-gray-700 px-3 py-1 rounded-full">.json</span>
              </div>
            </div>
          ) : (
            <div className="text-center">
              <div className="flex items-center justify-center mb-4">
                <div className="bg-green-500/20 p-3 rounded-full mr-3">
                  <FileText className="w-8 h-8 text-green-400" />
                </div>
                <div className="text-left flex-1">
                  <h4 className="text-lg font-semibold text-green-400">{file.name}</h4>
                  <p className="text-gray-400 text-sm">{formatFileSize(file.size)}</p>
                </div>
                <button
                  onClick={removeFile}
                  className="text-gray-400 hover:text-red-400 transition-colors p-2"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {uploadSuccess && (
                <div className="flex items-center justify-center text-green-400 mb-4">
                  <CheckCircle className="w-5 h-5 mr-2" />
                  <span>File uploaded successfully!</span>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Upload Button */}
        {file && !uploadSuccess && (
          <div className="mt-6">
            <button
              onClick={handleUpload}
              disabled={uploading}
              className={`w-full flex items-center justify-center px-6 py-4 rounded-xl font-semibold text-lg transition-all duration-300 ${
                uploading
                  ? 'bg-gray-600 cursor-not-allowed'
                  : 'bg-gradient-to-r from-green-600 to-green-500 hover:from-green-500 hover:to-green-400 hover:scale-105 hover:shadow-lg hover:shadow-green-500/25'
              }`}
            >
              {uploading ? (
                <>
                  <div className="animate-spin w-5 h-5 border-2 border-white border-t-transparent rounded-full mr-3"></div>
                  Uploading...
                </>
              ) : (
                <>
                  <Upload className="w-5 h-5 mr-3" />
                  Upload File
                </>
              )}
            </button>
          </div>
        )}

        {/* ✅ Display Result */}
        {result && (
          <div className="mt-8 p-4 bg-green-800/30 border border-green-500/20 rounded-xl">
            <h3 className="text-lg font-bold text-green-400 mb-3">Analysis Summary</h3>
            <ul className="text-sm text-gray-300 space-y-1">
              <li>🟢 Total Messages: <strong>{result.total_messages}</strong></li>
              <li>🔴 Toxic Messages: <strong>{result.toxic_messages}</strong></li>
              <li>📊 Toxicity %: <strong>{result.toxicity_percentage}%</strong></li>
              <li>👤 Top Sender(s): <strong>{Object.keys(result.analysis_by_sender).slice(0, 2).join(', ')}</strong></li>
            </ul>
          </div>
        )}

        {/* Info Section */}
        <div className="mt-8 p-4 bg-blue-500/10 rounded-xl border border-blue-500/20">
          <div className="flex items-start">
            <AlertCircle className="w-5 h-5 text-blue-400 mt-0.5 mr-3 flex-shrink-0" />
            <div className="text-sm text-gray-300">
              <p className="font-medium text-blue-400 mb-1">How to export WhatsApp chats:</p>
              <ul className="space-y-1 text-gray-400">
                <li>• Open WhatsApp and go to the chat you want to export</li>
                <li>• Tap the three dots → More → Export chat</li>
                <li>• Choose "Without Media" for faster processing</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
