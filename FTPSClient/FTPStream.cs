/*
 *  Copyright 2008 Alessandro Pilotti
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA 
 */

namespace AlexPilotti.FTPS.Common
{
    using System.IO;

    /// <inheritdoc />
    internal delegate void FTPStreamCallback();

    /// <summary>
    /// Encapsulates a Stream used during FTP get and put commands.
    /// </summary>
    public class FTPStream : Stream
    {
        /// <summary>
        /// 
        /// </summary>
        public enum EAllowedOperation
        {

            /// <summary>
            /// 
            /// </summary>
            Read = 1,
            /// <summary>
            /// 
            /// </summary>
            Write = 2
        }

        private readonly Stream _innerStream;
        private readonly FTPStreamCallback _streamClosedCallback;
        private readonly EAllowedOperation _allowedOp;

        internal FTPStream(Stream innerStream, EAllowedOperation allowedOp, FTPStreamCallback streamClosedCallback)
        {
            _innerStream = innerStream;
            _streamClosedCallback = streamClosedCallback;
            _allowedOp = allowedOp;
        }

        /// <inheritdoc />
        public override bool CanRead => _innerStream.CanRead && (_allowedOp & EAllowedOperation.Read) == EAllowedOperation.Read;

        /// <inheritdoc />
        public override bool CanSeek => _innerStream.CanSeek;

        /// <inheritdoc />
        public override bool CanWrite => _innerStream.CanWrite && (_allowedOp & EAllowedOperation.Write) == EAllowedOperation.Write;

        /// <inheritdoc />
        public override void Flush()
        {
            _innerStream.Flush();
        }

        /// <inheritdoc />
        public override long Length => _innerStream.Length;

        /// <inheritdoc />
        public override long Position
        {
            get => _innerStream.Position;
            set => _innerStream.Position = value;
        }

        /// <inheritdoc />
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (!CanRead)
                throw new FTPException("Operation not allowed");

            return _innerStream.Read(buffer, offset, count);
        }

        /// <inheritdoc />
        public override long Seek(long offset, SeekOrigin origin)
        {
            return _innerStream.Seek(offset, origin);
        }

        /// <inheritdoc />
        public override void SetLength(long value)
        {
            _innerStream.SetLength(value);
        }

        /// <inheritdoc />
        public override void Write(byte[] buffer, int offset, int count)
        {
            if (!CanWrite)
                throw new FTPException("Operation not allowed");

            _innerStream.Write(buffer, offset, count);
        }

        /// <inheritdoc />
        public override void Close()
        {
            base.Close();
            _streamClosedCallback();
        }
    }
}
