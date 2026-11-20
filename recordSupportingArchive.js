import yazl from 'yazl';

function archiveEntryName(file, usedNames) {
  const basename = String(file.originalname || 'supporting-file')
    .replace(/\\/g, '/')
    .split('/')
    .pop()
    .replace(/[\u0000-\u001f\u007f]/g, '_')
    .trim();
  const safeName = !basename || basename === '.' || basename === '..' ? 'supporting-file' : basename;
  const dot = safeName.lastIndexOf('.');
  const stem = dot > 0 ? safeName.slice(0, dot) : safeName;
  const extension = dot > 0 ? safeName.slice(dot) : '';
  let candidate = safeName;
  let suffix = 2;
  while (usedNames.has(candidate.toLowerCase())) candidate = `${stem} (${suffix++})${extension}`;
  usedNames.add(candidate.toLowerCase());
  return candidate;
}

export async function createSupportingArchive(files) {
  if (!Array.isArray(files) || files.length === 0) return null;
  if (files.some(file => !Buffer.isBuffer(file.buffer))) {
    throw new TypeError('Every supporting file must have an in-memory buffer.');
  }

  if (files.length === 1 && /\.zip$/i.test(files[0].originalname || '')) {
    const file = files[0];
    return {
      buffer: file.buffer,
      name: String(file.originalname).replace(/\\/g, '/').split('/').pop(),
      mime: 'application/zip',
      size: file.buffer.length,
      archive: true,
      contents: null,
    };
  }

  const zip = new yazl.ZipFile();
  const usedNames = new Set();
  const contents = files.map(file => {
    const archiveName = archiveEntryName(file, usedNames);
    zip.addBuffer(file.buffer, archiveName);
    return {
      name: String(file.originalname || archiveName).replace(/\\/g, '/').split('/').pop(),
      archive_name: archiveName,
      mime: file.mimetype || 'application/octet-stream',
      size: file.buffer.length,
    };
  });

  const chunks = [];
  const buffer = await new Promise((resolve, reject) => {
    const output = zip.outputStream;
    output.on('data', chunk => chunks.push(chunk));
    output.once('error', reject);
    output.once('end', () => resolve(Buffer.concat(chunks)));
    try {
      zip.end();
    } catch (error) {
      reject(error);
    }
  });

  return {
    buffer,
    name: 'supporting-files.zip',
    mime: 'application/zip',
    size: buffer.length,
    archive: true,
    contents,
  };
}
