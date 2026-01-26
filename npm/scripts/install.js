#!/usr/bin/env node

const https = require('https');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const REPO = 'h3nr1-d14z/nat-gate';
const BIN_DIR = path.join(__dirname, '..', 'bin');
const BIN_PATH = path.join(BIN_DIR, 'nat-gate');

function getPlatformInfo() {
    const platform = process.platform;
    const arch = process.arch;

    if (platform !== 'linux') {
        console.error(`Error: nat-gate only supports Linux. Current platform: ${platform}`);
        process.exit(1);
    }

    let binaryName;
    if (arch === 'x64') {
        binaryName = 'nat-gate-linux-x86_64';
    } else if (arch === 'arm64') {
        binaryName = 'nat-gate-linux-aarch64';
    } else {
        console.error(`Error: Unsupported architecture: ${arch}`);
        process.exit(1);
    }

    return binaryName;
}

function getLatestRelease() {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'api.github.com',
            path: `/repos/${REPO}/releases/latest`,
            headers: {
                'User-Agent': 'nat-gate-npm-installer'
            }
        };

        https.get(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const release = JSON.parse(data);
                    if (release.tag_name) {
                        resolve(release);
                    } else {
                        reject(new Error('No releases found'));
                    }
                } catch (e) {
                    reject(e);
                }
            });
        }).on('error', reject);
    });
}

function downloadFile(url, dest) {
    return new Promise((resolve, reject) => {
        const file = fs.createWriteStream(dest);

        const request = (url) => {
            https.get(url, {
                headers: { 'User-Agent': 'nat-gate-npm-installer' }
            }, (res) => {
                // Handle redirects
                if (res.statusCode === 302 || res.statusCode === 301) {
                    request(res.headers.location);
                    return;
                }

                if (res.statusCode !== 200) {
                    reject(new Error(`Failed to download: ${res.statusCode}`));
                    return;
                }

                res.pipe(file);
                file.on('finish', () => {
                    file.close();
                    resolve();
                });
            }).on('error', (err) => {
                fs.unlink(dest, () => {});
                reject(err);
            });
        };

        request(url);
    });
}

async function main() {
    console.log('Installing nat-gate binary...');

    const binaryName = getPlatformInfo();
    console.log(`Platform: linux, Architecture: ${process.arch}`);
    console.log(`Binary: ${binaryName}`);

    // Ensure bin directory exists
    if (!fs.existsSync(BIN_DIR)) {
        fs.mkdirSync(BIN_DIR, { recursive: true });
    }

    try {
        // Get latest release info
        console.log('Fetching latest release...');
        const release = await getLatestRelease();
        console.log(`Found release: ${release.tag_name}`);

        // Find the correct asset
        const asset = release.assets.find(a => a.name === binaryName);
        if (!asset) {
            throw new Error(`Binary ${binaryName} not found in release ${release.tag_name}`);
        }

        // Download the binary
        console.log(`Downloading ${binaryName}...`);
        await downloadFile(asset.browser_download_url, BIN_PATH);

        // Make executable
        fs.chmodSync(BIN_PATH, 0o755);

        console.log('nat-gate installed successfully!');
        console.log(`Binary location: ${BIN_PATH}`);

        // Verify installation
        try {
            const version = execSync(`"${BIN_PATH}" --version`, { encoding: 'utf8' });
            console.log(`Version: ${version.trim()}`);
        } catch (e) {
            // Binary might not run on this platform during npm install
            console.log('Note: Binary downloaded but could not verify (this is normal during cross-platform installs)');
        }

    } catch (error) {
        console.error('Installation failed:', error.message);
        console.error('');
        console.error('You can manually download from:');
        console.error(`  https://github.com/${REPO}/releases/latest`);
        process.exit(1);
    }
}

main();
