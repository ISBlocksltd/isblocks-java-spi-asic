package com.isblocks.signingblock.asicsigner;

import com.isblocks.signedblock.api.SignedBlockManager;
import com.isblocks.signedblock.api.SigningProvider;

public class ASICSigningProvider implements SigningProvider {

    @Override
    public SignedBlockManager create() {
        return new ASICSigningManager();
    }
}
