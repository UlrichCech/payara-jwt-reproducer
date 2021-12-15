/*
 * Copyright (c) 2018 Ulrich Cech - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Ulrich Cech <ulrich@ulrichcech.de>, 2018
 */
package de.test.platform;

/**
 * @author Ulrich Cech
 */
public class PlatformException extends RuntimeException {

    private static final long serialVersionUID = 6897463919940826522L;

    public PlatformException(Exception causedException) {
        super(causedException);
    }

    public PlatformException(String message) {
        super(message);
    }

}
