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

        Stream innerStream;
        FTPStreamCallback streamClosedCallback;
        EAllowedOperation allowedOp;

        internal FTPStream(Stream innerStream, EAllowedOperation allowedOp, FTPStreamCallback streamClosedCallback)
        {
            this.innerStream = innerStream;
            this.streamClosedCallback = streamClosedCallback;
            this.allowedOp = allowedOp;
        }

        /// <inheritdoc />
        public override bool CanRead => innerStream.CanRead && (allowedOp & EAllowedOperation.Read) == EAllowedOperation.Read;

        /// <inheritdoc />
        public override bool CanSeek => innerStream.CanSeek;

        /// <inheritdoc />
        public override bool CanWrite => innerStream.CanWrite && (allowedOp & EAllowedOperation.Write) == EAllowedOperation.Write;

        /// <inheritdoc />
        public override void Flush()
        {
            innerStream.Flush();
        }

        /// <inheritdoc />
        public override long Length => innerStream.Length;

        /// <inheritdoc />
        public override long Position
        {
            get => innerStream.Position;
            set => innerStream.Position = value;
        }

        /// <inheritdoc />
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (!CanRead)
                throw new FTPException("Operation not allowed");

            return innerStream.Read(buffer, offset, count);
        }

        /// <inheritdoc />
        public override long Seek(long offset, SeekOrigin origin)
        {
            return innerStream.Seek(offset, origin);
        }

        /// <inheritdoc />
        public override void SetLength(long value)
        {
            innerStream.SetLength(value);
        }

        /// <inheritdoc />
        public override void Write(byte[] buffer, int offset, int count)
        {
            if (!CanWrite)
                throw new FTPException("Operation not allowed");

            innerStream.Write(buffer, offset, count);
        }

        /// <inheritdoc />
        public override void Close()
        {
            base.Close();
            streamClosedCallback();
        }
    }
}
